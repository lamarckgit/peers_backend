import base64
import hashlib
import hmac
import logging
import os
import ssl
import threading
import time
import uuid

import fastapi

from classes.database_class import Database
from collections import deque, OrderedDict
from contextlib import asynccontextmanager
from functions import response_module # Not from functions.response_module import * because duplicate method name conflicts
#from constants import Constants
from fastapi import FastAPI, Request, HTTPException, Depends, status, Body, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm, APIKeyHeader
from fastapi.templating import Jinja2Templates
from fastapi import BackgroundTasks
from fastapi.responses import FileResponse
from license_manager import LicenseManager
from logging.handlers import TimedRotatingFileHandler
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import HTMLResponse
from typing import Dict, List, Optional

# 1. Create global instances
license_manager = LicenseManager()
license_manager.ensure_constants()    # Make sure constants are loaded!
# Each customer instance has its OWN database (DATABASE_URL comes from the
# license-issued constants and may point at its own MariaDB host). A modest
# per-instance pool is a sane default for a single-worker app; bump it per
# instance via env if one customer needs more. Only when several instances
# share one MariaDB host do these add up against that host's max_connections.
database = Database(
    license_manager.constants["DATABASE_URL"],
    pool_size=int(os.environ.get("DB_POOL_SIZE", "5")),
    max_overflow=int(os.environ.get("DB_MAX_OVERFLOW", "5")),
)
license_manager_thread = None
snapshot_cleanup_thread = None
# Ensure the directories exists
PROFILE_DIR = "static/profile_images"
os.makedirs(PROFILE_DIR, exist_ok=True)
SNAPSHOT_DIR = "static/snapshots"
os.makedirs(SNAPSHOT_DIR, exist_ok=True)
# Additional "about me" profile images: stored as <uuid>-<seq>.jpg; their display order + the in-use
# sequence numbers live in the user.image_order column. MAX mirrors the app's 5 "about me" slots.
ADDITIONAL_DIR = "static/additional_images"
os.makedirs(ADDITIONAL_DIR, exist_ok=True)
MAX_ADDITIONAL_IMAGES = 5
# Doorbell snapshots are never deleted by the request path; clean them up
# in-process so a customer deployment is self-contained (no external cron/timer).
SNAPSHOT_RETENTION_DAYS = int(os.environ.get("SNAPSHOT_RETENTION_DAYS", "14"))
SNAPSHOT_CLEANUP_INTERVAL_S = int(os.environ.get("SNAPSHOT_CLEANUP_INTERVAL_S", str(24 * 3600)))

# 2. Background thread runners
def run_license_manager():
    license_manager.daily_renewal_loop()

def cleanup_snapshots_once():
    """Delete this instance's snap_*.jpg older than SNAPSHOT_RETENTION_DAYS."""
    cutoff = time.time() - SNAPSHOT_RETENTION_DAYS * 86400
    removed = 0
    try:
        with os.scandir(SNAPSHOT_DIR) as entries:
            for entry in entries:
                if not (entry.is_file() and entry.name.startswith("snap_") and entry.name.endswith(".jpg")):
                    continue
                try:
                    if entry.stat().st_mtime < cutoff:
                        os.remove(entry.path)
                        removed += 1
                except OSError:
                    continue  # file vanished or unreadable; skip
    except FileNotFoundError:
        return
    if removed:
        logging.info(f"Snapshot cleanup: removed {removed} files older than {SNAPSHOT_RETENTION_DAYS}d")

def run_snapshot_cleanup():
    while True:
        try:
            cleanup_snapshots_once()
        except Exception as e:
            logging.error(f"Snapshot cleanup error: {e}")
        time.sleep(SNAPSHOT_CLEANUP_INTERVAL_S)

# 3. Lifespan context
@asynccontextmanager
async def lifespan(app: FastAPI):
    global license_manager_thread, snapshot_cleanup_thread
    if not license_manager_thread or not license_manager_thread.is_alive():
        license_manager_thread = threading.Thread(target=run_license_manager, daemon=True)
        license_manager_thread.start()
        logging.info("Started LicenseManager renewal thread.")
    if not snapshot_cleanup_thread or not snapshot_cleanup_thread.is_alive():
        snapshot_cleanup_thread = threading.Thread(target=run_snapshot_cleanup, daemon=True)
        snapshot_cleanup_thread.start()
        logging.info("Started snapshot cleanup thread.")
    yield
    # Optionally add cleanup logic here if needed
    if hasattr(license_manager, "db") and license_manager.db is not None:
        license_manager.db.close()

# 4. FastAPI app instance
app = FastAPI(lifespan=lifespan)

# 5. Database dependency
def get_db():
    # Dependency to get a new database session.
    db = database.create_session()
    try:
        yield db
    finally:
        db.close()  # Ensure session is closed

db = next(get_db())
license_manager.db = db

log_handler = TimedRotatingFileHandler(
    "logs/safexs.log",
    when="midnight",  # Rotate logs every midnight
    interval = 1,
    backupCount = 30,  # Keep logs for 30 days
    #maxBytes = 5 * 1024 * 1024  # 5 MB //need custom SizeTimedRotatingFileHandler
)
# Configure logging
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s",
                    handlers=[log_handler])

class LogMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        #print("🔹 Incoming request headers:", request.headers)
        # Log the incoming request details
        logging.info(f"Incoming request: {request.client.host} {request.method} {request.url} {request.headers.get('user-agent')}")
        # Get the response
        response = await call_next(request)
        # Log the response status code
        logging.info(f"Response status: {response.status_code}")
        return response

# Global cap on queued offline control ops (CHAT_EDIT/CHAT_DELETE) across ALL peers. ~each op is a small
# JSON dict (~a few hundred bytes), so 50k ≈ ~15-20 MB worst case. When full, the oldest op is FIFO-evicted.
MAX_PENDING_OPS = int(os.environ.get("PEERS_MAX_PENDING_OPS", "50000"))
# Byte cap on the queued offline messages (photos are large base64) — bounds memory regardless of count.
# FIFO-evict the oldest until under both caps. Default 100 MB.
MAX_PENDING_BYTES = int(os.environ.get("PEERS_MAX_PENDING_BYTES", str(100 * 1024 * 1024)))


def _op_size(data: dict) -> int:
    """Rough byte size of a queued op (the big contributor is a photo's/voice's base64 payload)."""
    return (len(data.get("imageData") or "") + len(data.get("audioData") or "")
            + len(data.get("contactCard") or "") + len(data.get("text") or "") + 256)
# Global cap on cached live-location last-positions (one per active share per target). Bounded so a flood
# of live shares can't grow memory without limit.
MAX_LIVE_POSITIONS = int(os.environ.get("PEERS_MAX_LIVE_POSITIONS", "20000"))

# Store active connections: bell_id -> WebSocket
class ConnectionManager:
    def __init__(self):
        # We store connections mapped by a unique ID (e.g., "bell_101", "safe_user_5")
        self.active_connections: Dict[str, WebSocket] = {}
        # Per-receiver app-icon badge counter for offline friend-message pushes. Incremented on each
        # such push (carried in aps.badge), reset when the receiver reconnects (back online/foreground).
        self.pending_badge: Dict[str, int] = {}
        # Queue of control ops (CHAT_EDIT / CHAT_DELETE) that couldn't be delivered while the target was
        # offline/killed — flushed when that peer reconnects. In-memory (lost on a backend restart, which
        # is rare); deletes/edits are eventually-consistent so that's acceptable.
        #   pending_ops:     seq -> (target_id, op)   — global insertion order (OrderedDict = FIFO)
        #   pending_by_peer: target_id -> deque(seq)  — per-peer index for O(1) flush
        # Bounded GLOBALLY at MAX_PENDING_OPS: when full, the OLDEST op is evicted (FIFO), so a flood of
        # deletes for killed peers can't grow memory without bound / crash the server.
        self.pending_ops: "OrderedDict[int, tuple]" = OrderedDict()   # seq -> (target_id, data, size)
        self.pending_by_peer: Dict[str, deque] = {}
        self._op_seq = 0
        self._pending_bytes = 0
        # Live-location last-position cache: target_id -> {msgId -> latest LOCATION_UPDATE data}. Flushed
        # to the target on reconnect so a backgrounded/returning receiver sees an up-to-date pin.
        self.live_positions: Dict[str, dict] = {}
        self._live_count = 0

    async def connect(self, client_id: str, websocket: WebSocket):
        await websocket.accept()
        self.active_connections[client_id] = websocket
        self.pending_badge.pop(client_id, None)   # back online → clear the app-icon badge counter
        print(f"Client connected: {client_id}")
        # Deliver any control ops queued while this peer was offline (e.g. a Sender deleted a message
        # while the receiver had the app killed).
        seqs = self.pending_by_peer.pop(client_id, None)
        if seqs:
            ops = []
            for seq in seqs:
                entry = self.pending_ops.pop(seq, None)
                if entry:
                    self._pending_bytes -= entry[2]
                    ops.append(entry[1])
            for op in ops:
                try:
                    await websocket.send_json(op)
                except Exception as e:
                    print(f"flush pending op to {client_id[:8]} failed: {e}")
                    break
            print(f"flushed {len(ops)} queued op(s) to {client_id[:8]}")
        # Deliver the latest position of any live-location shares aimed at this peer (skip expired).
        positions = self.live_positions.pop(client_id, None)
        if positions:
            self._live_count -= len(positions)
            now = time.time()
            for mid, d in positions.items():
                lu = d.get("liveUntil") or 0
                if lu and lu < now:
                    continue
                try:
                    await websocket.send_json(d)
                except Exception as e:
                    print(f"flush live position to {client_id[:8]} failed: {e}")
                    break
            print(f"flushed live position(s) to {client_id[:8]}")

    def cache_live(self, target_id: str, data: dict):
        mid = data.get("msgId")
        if not mid:
            return
        bucket = self.live_positions.setdefault(target_id, {})
        if mid not in bucket:
            if self._live_count >= MAX_LIVE_POSITIONS:
                return                      # at cap → don't track new shares (best-effort)
            self._live_count += 1
        bucket[mid] = data

    def clear_live(self, target_id: str, mid):
        bucket = self.live_positions.get(target_id)
        if bucket and mid in bucket:
            del bucket[mid]
            self._live_count -= 1
            if not bucket:
                self.live_positions.pop(target_id, None)

    def enqueue(self, target_id: str, data: dict):
        self._op_seq += 1
        seq = self._op_seq
        size = _op_size(data)
        self.pending_ops[seq] = (target_id, data, size)
        self.pending_by_peer.setdefault(target_id, deque()).append(seq)
        self._pending_bytes += size
        # FIFO eviction when over EITHER the count or the byte cap → drop the oldest queued op(s).
        while len(self.pending_ops) > MAX_PENDING_OPS or self._pending_bytes > MAX_PENDING_BYTES:
            if not self.pending_ops:
                break
            old_seq, (old_target, _, old_size) = self.pending_ops.popitem(last=False)
            self._pending_bytes -= old_size
            dq = self.pending_by_peer.get(old_target)
            if dq:
                if dq and dq[0] == old_seq:    # the evicted op is that peer's oldest
                    dq.popleft()
                else:
                    try: dq.remove(old_seq)
                    except ValueError: pass
                if not dq:
                    self.pending_by_peer.pop(old_target, None)

    def next_badge(self, client_id: str) -> int:
        self.pending_badge[client_id] = self.pending_badge.get(client_id, 0) + 1
        return self.pending_badge[client_id]

    def disconnect(self, client_id: str):
        if client_id in self.active_connections:
            del self.active_connections[client_id]
            print(f"Client disconnected: {client_id}")

    async def send_personal_message(self, message: dict, client_id: str):
        if client_id in self.active_connections:
            await self.active_connections[client_id].send_json(message)
        else:
            print(f"Target {client_id} not connected/found.")


# Create the FastAPI app
app = FastAPI(lifespan=lifespan)
manager = ConnectionManager()

# Add the logging middleware to the app
# app.add_middleware(LogMiddleware)

@app.websocket("/ws/{client_id}")
async def websocket_endpoint(websocket: WebSocket, client_id: str):
    await manager.connect(client_id, websocket)
    try:
        while True:
            # Receive JSON data (Offer, Answer, or Candidate)
            data = await websocket.receive_json()

            # The client must specify who the message is for
            target_id = data.get("target")

            if target_id:
                # Forward the exact message to the target peer (stamping the sender so the
                # recipient knows who it's from).
                data["sender"] = client_id
                msg_type = data.get("type")
                print(f"relay {client_id} → {target_id}: {msg_type}")

                # Cache live-location position (delivered or not) so a reconnecting receiver gets the
                # latest pin; clear it when the share stops.
                if msg_type == "LOCATION_UPDATE":
                    manager.cache_live(target_id, data)
                elif msg_type == "LOCATION_STOP":
                    manager.clear_live(target_id, data.get("msgId"))

                # A photo / contact / (static) location message can't have its payload carried by the
                # offline push. ALWAYS queue it for friends (independent of the live send below — a killed
                # app can leave a stale socket that accepts the write, so "delivered" isn't reliable). The
                # receiver de-dups by msgId, so an online receiver that already got it ignores the flush.
                # The queue is byte-bounded (MAX_PENDING_BYTES), so queued photos can't exhaust memory.
                if (msg_type == "CHAT_MESSAGE" and not data.get("liveUntil")
                        and (data.get("contactCard") or data.get("imageData") or data.get("audioData")
                             or data.get("latitude") is not None)):
                    try:
                        s_q = database.create_session()
                        try:
                            if response_module.are_friends(s_q, client_id, target_id):
                                manager.enqueue(target_id, data)
                                kind = ("photo" if data.get("imageData") else "audio" if data.get("audioData")
                                        else "contact" if data.get("contactCard") else "location")
                                print(f"relay: queued {kind} for {target_id[:8]}")
                        finally:
                            s_q.close()
                    except Exception as e:
                        print(f"relay queue media error: {e}")

                # Try a live delivery first. A killed app may leave a stale socket in
                # active_connections (its disconnect not yet detected); sending into it raises,
                # so we drop it and fall through to the FCM push instead of silently losing the
                # request.
                delivered = False
                ws = manager.active_connections.get(target_id)
                if ws is not None:
                    try:
                        await ws.send_json(data)
                        delivered = True
                    except Exception as e:
                        print(f"relay: send to {target_id[:8]} failed ({e}); dropping stale socket")
                        manager.disconnect(target_id)

                if not delivered:
                    # A friend's chat message to an offline/backgrounded peer → VISIBLE "new message"
                    # push: banner (title=sender, body=text) + system sound + app-icon badge, carrying
                    # the text + msgId so the app stores it (de-dup). Only between friends (a non-friend
                    # chat uses the accept-dialog flow and never silently messages an offline peer).
                    if msg_type == "CHAT_MESSAGE":
                        try:
                            s = database.create_session()
                            try:
                                if response_module.are_friends(s, client_id, target_id):
                                    fcm_token, _, _ = response_module.get_peer_push_info(s, target_id)
                                    _, sender_name, _ = response_module.get_peer_push_info(s, client_id)
                                    if fcm_token:
                                        badge = manager.next_badge(target_id)
                                        ok = response_module.send_chat_message_push(
                                            fcm_token, client_id, sender_name,
                                            data.get("text") or "", badge, data.get("msgId") or "")
                                        print(f"relay: chat-msg push to {target_id[:8]} sent={ok} badge={badge}")
                                    else:
                                        print(f"relay: offline friend {target_id[:8]} has no push token")
                                else:
                                    print(f"relay: CHAT_MESSAGE to offline non-friend {target_id[:8]} dropped")
                            finally:
                                s.close()
                        except Exception as e:
                            print(f"relay chat-msg push error: {e}")
                    # Signal types that warrant a push when the target is offline
                    # (backgrounded/killed): chat request, call request + the friend handshake.
                    elif msg_type in ("CHAT_REQUEST", "CALL_REQUEST", "FRIEND_REQUEST", "FRIEND_ACCEPT", "NOFRIEND", "UNFRIEND"):
                        try:
                            s = database.create_session()
                            try:
                                # Privacy: only a Friend may wake a killed/offline peer for a chat or
                                # call. The friend handshake itself (FRIEND_*) is always allowed so
                                # friend requests/answers can still reach an offline peer.
                                if msg_type in ("CHAT_REQUEST", "CALL_REQUEST") and not response_module.are_friends(s, client_id, target_id):
                                    print(f"relay: {msg_type} to offline {target_id[:8]} suppressed (sender not a friend)")
                                else:
                                    fcm_token, _, voip_token = response_module.get_peer_push_info(s, target_id)
                                    _, sender_name, _ = response_module.get_peer_push_info(s, client_id)
                                    # Carry the call's audio/video flag through to the push.
                                    extra = {"video": "1" if data.get("video") else "0"} if msg_type == "CALL_REQUEST" else None
                                    sent = False
                                    # A CALL to a CallKit-capable peer → native VoIP push (rings via
                                    # CallKit from a killed/locked state). Everything else (chat/friend,
                                    # or a peer with no VoIP token e.g. China) → FCM notification.
                                    if msg_type == "CALL_REQUEST" and voip_token:
                                        sent = response_module.send_voip_push(voip_token, msg_type, client_id, sender_name, extra)
                                        print(f"relay: VoIP push to {target_id[:8]} {msg_type} sent={sent}")
                                    if not sent and fcm_token:
                                        sent = response_module.send_signal_push(fcm_token, msg_type, client_id, sender_name, extra)
                                        print(f"relay: FCM fallback to {target_id[:8]} {msg_type} sent={sent}")
                                    if not sent and not voip_token and not fcm_token:
                                        print(f"relay: offline target {target_id[:8]} has no push token")
                            finally:
                                s.close()
                        except Exception as e:
                            print(f"relay FCM fallback error: {e}")
                    elif msg_type in ("CHAT_EDIT", "CHAT_DELETE"):
                        # Hold the edit/delete and deliver it when the (killed/offline) target returns,
                        # so the Sender's edit/delete still applies at the Receiver's end. `data` already
                        # has the sender stamped, so the flushed op is processed exactly like a live one.
                        manager.enqueue(target_id, data)
                        print(f"relay: queued {msg_type} for offline {target_id[:8]}")
                    else:
                        print(f"relay: target {target_id[:8]} offline; dropping {msg_type}")

    except WebSocketDisconnect:
        manager.disconnect(client_id)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
templates = Jinja2Templates(directory="templates")
ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ssl_context.load_cert_chain("fullchain.pem", keyfile="privkey.pem")
# Use FastAPI's APIKeyHeader dependency to fetch a secret key from headers
api_key_header = APIKeyHeader(name="x-api-key")


@app.get("/health")
async def health():
    """Per-customer liveness + license-renewal health for monitoring.

    Returns 200 when constants are loaded and the last daily renewal
    succeeded, 503 otherwise — so an uptime monitor flips on a stuck
    renewal (which would otherwise silently expire the license next day).
    Deliberately exposes no secrets (no UUID/DB/keys)."""
    constants = license_manager.constants or {}
    healthy = bool(constants) and license_manager.last_renewal_error is None
    return JSONResponse(
        status_code=200 if healthy else 503,
        content={
            "status": "ok" if healthy else "degraded",
            "last_renewal_date": license_manager.last_renewal_date,
            "last_renewal_error": license_manager.last_renewal_error,
            "license_expiry_date": constants.get("LICENSE_EXPIRY_DATE"),
        },
    )

# "About me" is limited to 256 USER-PERCEIVED characters on the client (grapheme clusters, so an emoji or
# flag counts as 1). One such grapheme can expand to several Unicode code points (a flag = 2, a ZWJ family
# = 7, etc.), and both this code-point cap and the DB column count code points — so the budget is 256 × a
# generous per-grapheme factor. 2048 covers 256 of even the heaviest common emoji; it bounds abuse without
# rejecting any sane bio. KEEP THIS IN SYNC WITH THE about_me COLUMN WIDTH (see migration note).
ABOUT_ME_MAX_CODEPOINTS = 2048

class RequestUuid(BaseModel):
    uuid: str

class RequestCreatePeer(BaseModel):
    name: str
    about_me: Optional[str] = Field(default=None, max_length=ABOUT_ME_MAX_CODEPOINTS)
    image_data: Optional[str] = None

class RequestUpdatePeer(BaseModel):
    uuid: str
    name: Optional[str] = None
    about_me: Optional[str] = Field(default=None, max_length=ABOUT_ME_MAX_CODEPOINTS)
    image_data: Optional[str] = None

class RequestUpdatePeerImage(BaseModel):
    uuid: str
    image_data: str

class RequestUpdatePeerName(BaseModel):
    uuid: str
    name: str

class RequestUpdatePeerAboutMe(BaseModel):
    uuid: str
    about_me: str = Field(max_length=ABOUT_ME_MAX_CODEPOINTS)

# --- Additional "about me" images ---
class RequestAddImage(BaseModel):
    uuid: str
    image_data: str
    order_no: int = 0            # display position to insert the new photo at (the app appends → end)

class RequestUpdateImage(BaseModel):
    uuid: str
    image_data: str
    order_no: int               # display position whose photo is being replaced

class RequestUpdateImageOrder(BaseModel):
    uuid: str
    new_order: str              # new display order as 0-based OLD positions, e.g. "2,0,1,3,4"

class RequestDeleteImage(BaseModel):
    uuid: str
    order_no: int               # display position to clear

class RequestPeerImages(BaseModel):
    uuid: str                   # the peer whose additional images are requested
    caller_uuid: str            # the authenticated requester (validates via check_peer_uuid)

class RequestPeersOnline(BaseModel):
    uuid: str          # the calling peer's own uuid (authenticated by check_peer_uuid)
    uuids: List[str]   # the peer uuids whose online/active status is being queried

class RequestAddFriend(BaseModel):
    uuid: str
    friend_uuid: str

class RequestBlockPeer(BaseModel):
    uuid: str          # the blocker (authenticated by check_peer_uuid)
    blocked_uuid: str  # the peer being blocked

class RequestActivateUser(BaseModel):
    uuid: str
    is_active: bool

class RequestAddUser(BaseModel):
    uuid: str
    email: str
    full_name: str
    location: str
    super_admin_support: bool
    email_support: bool

class RequestActivateUser(BaseModel):
    uuid: str
    is_active: bool

class RequestActivateUserLock(BaseModel):
    uuid: str
    id: int
    ble_id: str
    is_active: bool

class RequestId(BaseModel):
    uuid: str

# Peer profile lookup: `uuid` is the peer being viewed, `caller_uuid` is the requester's own id
# (authenticated by check_peer_uuid — lookups are only allowed for registered peers).
class RequestPeerLookup(BaseModel):
    uuid: str
    caller_uuid: str

class RequestUuIdId(BaseModel):
    uuid: str
    id: int

class RequestUuIdBleId(BaseModel):
    uuid: str
    ble_id: str

class RequestStoreFCMToken(BaseModel):
    uuid: str
    fcm_token: str

class RequestStoreVoipToken(BaseModel):
    uuid: str
    voip_token: str

class RequestLogOnline(BaseModel):
    uuid: str
    ble_id: str
    action_id: int
    is_success: bool
    link_id: str
    message: str
    temperature: int

class RequestPeripheral(BaseModel):
    user_id: int
    ble_id: str

class RequestRemote(BaseModel):
    uuid: str
    is_active: bool

class RequestRemoteShare(BaseModel):
    uuid: str
    ble_id: str
    action_id: int
    link_id: str
    message: str

class RequestNotifySafeXS(BaseModel):
    uuid: str
    bell_id: int
    image_data: Optional[str] = None

class RequestGetImage(BaseModel):
    image_filename: str

class RequestOpenBellXS(BaseModel):
    uuid: str
    ble_id: str

class RequestShareLink(BaseModel):
    uuid: str
    ble_id: str
    valid_from: str
    valid_to: str
    limit_uses: int
    reference: str

class RequestUser(BaseModel):
    user_id: int

class RequestUsers(BaseModel):
    uuid: str
    user_id: int

class RequestVerify2FA(BaseModel):
    email: str
    token: str
    uuid: str

class RequestLinkId(BaseModel):
    link_id: str

class RequestPassword(BaseModel):
    email: str

class RequestInvite(BaseModel):
    uuid: str
    email: str
    ble_id: str
    full_name: str
    location: str
    valid_from: str
    valid_to: str
    offline_support: bool
    remote_support: bool
    admin_support: bool
    send_keys: int
    email_support: bool

class RequestSetLock(BaseModel):
    uuid: str
    ble_id: str
    name: str
    location: str
    sig_duration: int
    auto_unlock_db: int
    remote_support: bool
    is_active: bool
    apply_remote_support_to_all_users: bool
    apply_active_to_all_users: bool

class RequestSetUser(BaseModel):
    uuid: str
    id: int
    email: str
    full_name: str
    location: str
    super_admin_support: bool

class RequestSetUserLock(BaseModel):
    uuid: str
    user_id: int
    ble_id: str
    valid_from: str
    valid_to: str
    offline_support: bool
    remote_support: bool
    auto_unlock_support: bool
    admin_support: bool
    send_keys: int

# A utility function to verify the secret key
def verify_api_key(api_key: str = Depends(api_key_header)):
    if api_key != license_manager.get_constants()["SECRET_API"]:
        raise HTTPException(status_code=401, detail="Invalid API Key")


async def check_peer_uuid(request: Request, db: Session = Depends(get_db)):
    """Auth gate for the PeersClub peer endpoints. On top of the shared X-API-Key it requires the
    caller to present its own peer uuid in the JSON body and that uuid to exist in the user table —
    rejecting unknown/forged/stale peers (e.g. a Keychain uuid left over after the DB row was
    removed). create_peer is exempt (the uuid doesn't exist yet). Reading request.json() here is
    safe: Starlette caches the body, so the endpoint's own Pydantic model still parses it."""
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid request body")
    # Authenticate the *calling* peer. On most endpoints the body's `uuid` IS the caller; on lookups
    # where `uuid` is the target being viewed (e.g. /v1/peer/), the caller's own id is sent as
    # `caller_uuid` and takes precedence so we validate the requester, not the requested.
    peer_hex = (body.get("caller_uuid") or body.get("uuid")) if isinstance(body, dict) else None
    if not isinstance(peer_hex, str) or not peer_hex:
        raise HTTPException(status_code=401, detail="Missing peer uuid")
    if not response_module.peer_exists(db, peer_hex):
        raise HTTPException(status_code=403, detail="Unknown peer")
    return peer_hex


async def check_credentials(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        return response_module.check_oauth_credentials(db, token, license_manager.constants)
    except Exception as e:
        return None

progress = 0

@app.get("/images/{filename}")
def get_image(filename: str):
    return FileResponse(f"images/{filename}", media_type="image/png")

@app.get("/v1/task_progress", response_class=HTMLResponse)
async def task_progress():
    global progress
    if progress >= 100:
        return '<div style="font-size: 50px; color: green;">✓ Task Complete!</div>'
    elif False:
        return '<div style="font-size: 50px; color: red;">X Task Failed!</div>'
    else:
        progress += 10
        return f'<div class="progress-bar" style="width: {progress}%">{progress}%</div>'

@app.get("/v1/progress", response_class=HTMLResponse)
async def progress_page(request: Request):
    return templates.TemplateResponse("progress.html", {"request": request})

def long_running_task():
    import time
    for i in range(10):
        time.sleep(1)  # Simulate task progress

@app.post("/v1/start_task")
async def start_task(background_tasks: BackgroundTasks):
    background_tasks.add_task(long_running_task)
    return {"message": "Opening started"}

@app.get("/v1/open_share", response_class=HTMLResponse)
async def open_share_lock(request: Request, link_id: str, db: Session = Depends(get_db)):
    try:
        # Check im link_id is valid
        request_row = response_module.get_share_request(db, link_id)
        if request_row:
            return templates.TemplateResponse(
                "confirm.html",
                {"request": request, "door": request_row["peripheral_name"], "link_id": link_id}
            )

    except Exception as e:
        # Only log erors = failed attempts
        message = str(e)
        message = message.replace("Exception error: ", "")
        response_module.log_online_action(db,"", "", 4, False, link_id, -1, message, 99)
        return JSONResponse(content={"success": False, "error": str(e)},status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

@app.post("/v1/get_share/", response_model=response_module.ResponseShareLink, dependencies=[Depends(verify_api_key)])
async def get_share_link(params: RequestShareLink, username: response_module.ResponseUsername = Depends(check_credentials), db: Session = Depends(get_db)):
    result = False
    message = params.reference
    try:
        if username: #if creditential valid => email
            response = response_module.set_share_link(db, params.ble_id, params.uuid, params.valid_from, params.valid_to, params.limit_uses, message, license_manager.constants)
            # result = response.success
            # print(f"response Open Remote RESULT: {result}")
            if response:
                return response
            else:
                message = "No link provided"
                return JSONResponse(content={"success": result, "error": message}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            raise Exception(f"Exception error: Unauthorized")

    except Exception as e:
        message = str(e)
        return JSONResponse(content={"success": result, "error": message}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
    # finally:
    #     message = message.replace("Exception error: ", "")
        # response_module.log_online_action(params.ble_id, params.uuid, 4, result, params.link_id, -1, message)

@app.post("/v1/start_open_share/", response_model=response_module.ResponseShare)
async def start_open_share(background_tasks: BackgroundTasks, link_data: RequestLinkId = Body(...), db: Session = Depends(get_db)):
    try:
        # Get properties of link_id, yes, 2nd call not to communicate parameters to HTML [Confirm] button
        request_row = response_module.get_share_request(db, link_data.link_id)
        message = request_row["reference"]
        uses_left = request_row["uses_left"]
        remote_share = RequestRemoteShare(uuid=request_row["phone_uuid"], ble_id=request_row["peripheral_ble_id"], action_id=4, link_id=link_data.link_id, message=message )
        response_remote = await open_remote_lock(remote_share)
        if not response_remote.error:
            # substract 1 from uses left and set in database
            uses_left -= 1
            response_module.set_share_uses(db, link_data.link_id)
        response = response_module.ResponseShare(uses_left=uses_left, success=response_remote.success, error=response_remote.error)
        return response

    except Exception as e:
        # Only log erors = failed attempts
        message = str(e)
        message = message.replace("Exception error: ", "")
        response_module.log_online_action(db,"", "", 4, False, link_data.link_id, -1, message, 99)
        return JSONResponse(content={"success": False, "error": str(e)},status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

@app.post("/v1/open_remote/", response_model=response_module.ResponseResult, dependencies=[Depends(verify_api_key)])
async def open_remote_lock(params: RequestRemoteShare,  username: response_module.ResponseUsername = Depends(check_credentials), db: Session = Depends(get_db)):
    result = False
    message = params.message
    try:
        if username: #if creditential valid => email
            if not isinstance(db, Session):
                db = Database(license_manager.constants["DATABASE_URL"]).create_session()
            response = await response_module.open_remote(db, params.ble_id, params.uuid, username.email, license_manager.constants)
            result = response.success
            # print(f"response Open Remote RESULT: {result}")
            if not result:
                message = response.error
            return response
        else:
            raise Exception(f"Exception error: Unauthorized")

    except Exception as e:
        message = str(e)
        return JSONResponse(content={"success": result, "error": message}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
    finally:
        message = message.replace("Exception error: ", "")
        response_module.log_online_action(db, params.ble_id, params.uuid, params.action_id, result, params.link_id, -1, message)

@app.post("/v1/open_online/", response_model=response_module.ResponseOpenOnline, dependencies=[Depends(verify_api_key)])
async def open_online_lock(params: RequestUuIdBleId, username: response_module.ResponseUsername = Depends(check_credentials), db: Session = Depends(get_db)):
    # This function is called when user is tapping lock to propagate the latest server time to the peripheral so its clock stays in sync
    try:
        if username: #if creditential valid => email
            response = response_module.get_online_payload(db, params.ble_id, params.uuid, license_manager.constants)
            # print(f"response Open Online: {response}")
            return response
        else:
            raise Exception(f"Exception error: Unauthorized")

    except Exception as e:
        return JSONResponse(content={"success": False, "error": str(e)}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

@app.post("/v1/nearby/", response_model=response_module.ResponseBLE, dependencies=[Depends(verify_api_key)])
async def get_nearby_locks(params: RequestUuIdBleId, username: response_module.ResponseUsername = Depends(check_credentials), db: Session = Depends(get_db)):
    try:
        if username: #if creditential valid => email
            response = response_module.get_nearby_properties(db, params.ble_id, params.uuid, license_manager.constants)
            # print(f"response Nearby: {response}")
            return response
        else:
            raise Exception(f"Exception error: Unauthorized")

    except ValueError as e:
        return JSONResponse(content={"success": False, "error": str(e)}, status_code=status.HTTP_400_BAD_REQUEST)
    except HTTPException as e:
        return JSONResponse(content={"success": False, "error": str(e)}, status_code=e.status_code)
    except Exception as e:
        return JSONResponse(content={"success": False, "error": str(e)}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

@app.post("/v1/phone_peripherals/", response_model=List[response_module.ResponseBLE], dependencies=[Depends(verify_api_key)])
async def get_nearby_locks(params: RequestId, username: response_module.ResponseUsername = Depends(check_credentials), db: Session = Depends(get_db)):
    try:
        if username: #if creditential valid => email
            response = response_module.get_phone_peripherals(db, params.uuid, license_manager.constants)
            # print(f"response Nearby: {response}")
            return response
        else:
            raise Exception(f"Exception error: Unauthorized")

    except ValueError as e:
        return JSONResponse(content={"success": False, "error": str(e)}, status_code=status.HTTP_400_BAD_REQUEST)
    except HTTPException as e:
        return JSONResponse(content={"success": False, "error": str(e)}, status_code=e.status_code)
    except Exception as e:
        return JSONResponse(content={"success": False, "error": str(e)}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)


@app.post("/v1/log_online_action/", response_model=response_module.ResponseResult, dependencies=[Depends(verify_api_key)])
async def log_online_action(params: RequestLogOnline, username: response_module.ResponseUsername = Depends(check_credentials), db: Session = Depends(get_db)):
    try:
        if username: #if creditential valid => email
            response = response_module.log_online_action(db, params.ble_id, params.uuid, params.action_id, params.is_success, params.link_id, -1, params.message, params.temperature)
            # print(f"response Online Action: {response}")
            return response
        else:
            raise Exception(f"Exception error: Unauthorized")

    except Exception as e:
        return JSONResponse(content={"success": False, "error": str(e)}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

# Endpoint for list of supported remote peripherals with OAuth2.0
@app.post("/v1/remote/", response_model=List[dict], dependencies=[Depends(verify_api_key)])
async def get_all_locks(params: RequestRemote, username: response_module.ResponseUsername = Depends(check_credentials), db: Session = Depends(get_db)):
    try:
        if username: #if creditential valid => email
            rows = response_module.get_all_properties(db, params.uuid, license_manager.constants, params.is_active)
            #response = JSONResponse(content=rows, status_code=status.HTTP_200_OK)
            response = JSONResponse(content=[dict(row) for row in rows], status_code=status.HTTP_200_OK)
            # print(f"response Remote: {response}")
            return response
        else:
            raise Exception(f"Exception error: Unauthorized")

    except Exception as e:
        return JSONResponse(content={"success": False, "error": str(e)}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

@app.post("/v1/create_peer/", response_model=response_module.ResponseCreatePeer, dependencies=[Depends(verify_api_key)])
async def create_peer(params: RequestCreatePeer, db: Session = Depends(get_db)):
    message = ""
    result = False
    peer_hex = ""
    try:
        peer = uuid.uuid4()
        peer_bytes = peer.bytes      # 16-byte value stored in the DB
        peer_hex = peer.hex          # 32-char ASCII representation (filename + response)
        if params.image_data:
            try:
                # 1. Create the specific filename requested
                # peer_{uuid_hex}.jpg
                filename = f"peer_{peer_hex}.jpg"
                file_path = os.path.join(PROFILE_DIR, filename)

                # 2. Decode and Save locally
                img_bytes = base64.b64decode(params.image_data)
                with open(file_path, "wb") as f:
                    f.write(img_bytes)

                # 3. Store the filename to send in notification
                image_filename = filename
                message = image_filename

            except Exception as img_err:
                message = f"Image save failed: {img_err}"
                image_filename = ""

        response = response_module.create_peer(db, peer_bytes, params.name, params.about_me)
        result = True
        return response

    except HTTPException as e:
        return JSONResponse(content={"success": False, "error": str(e)}, status_code=e.status_code)
    except Exception as e:
        return JSONResponse(content={"success": False, "error": str(e)}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
    finally:
        message = message.replace("Exception error: ", "")
        # No peripheral involved in peer creation; log against the new peer's hex uuid.
        response_module.log_online_action(db, "", peer_hex, 0, result, "", -1, message)

# Permanently deletes the calling peer: their user row, all friend links, and their profile image
# (static/profile_images/peer_{uuid}.jpg). X-API-Key + check_peer_uuid — a peer can only delete
# itself (the uuid in the body is the authenticated caller).
@app.post("/v1/delete_peer/", response_model=response_module.ResponseResult, dependencies=[Depends(verify_api_key), Depends(check_peer_uuid)])
async def delete_peer(params: RequestUuid, db: Session = Depends(get_db)):
    try:
        result = response_module.delete_peer(db, params.uuid)
        # Remove the profile image (peer_{uuid_hex}.jpg) if present.
        file_path = os.path.join(PROFILE_DIR, f"peer_{params.uuid}.jpg")
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
            except OSError as e:
                print(f"delete_peer: failed to remove image {file_path}: {e}")
        return result
    except HTTPException as e:
        return JSONResponse(content={"success": False, "error": str(e)}, status_code=e.status_code)
    except Exception as e:
        return JSONResponse(content={"success": False, "error": str(e)}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

# Registers a peer's FCM push token (so it can be woken/rung for an incoming chat while its app
# is backgrounded). X-API-Key only — peers have no OAuth session — keyed by uuid hex in the body
# ({"uuid": ..., "fcm_token": ...}), reusing the iOS postRequestForJson helper like create_peer.
@app.post("/v1/register_peer_token/", response_model=response_module.ResponseResult, dependencies=[Depends(verify_api_key), Depends(check_peer_uuid)])
async def register_peer_token(params: RequestStoreFCMToken, db: Session = Depends(get_db)):
    try:
        return response_module.register_peer_token(db, params.uuid, params.fcm_token)
    except HTTPException as e:
        return JSONResponse(content={"success": False, "error": str(e)}, status_code=e.status_code)
    except Exception as e:
        return JSONResponse(content={"success": False, "error": str(e)}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

# Stores a peer's PushKit VoIP token so the relay can wake it with a native CallKit incoming-call
# screen for a call (killed/locked). Same X-API-Key + uuid-hex-keyed pattern as register_peer_token.
@app.post("/v1/register_peer_voip_token/", response_model=response_module.ResponseResult, dependencies=[Depends(verify_api_key), Depends(check_peer_uuid)])
async def register_peer_voip_token(params: RequestStoreVoipToken, db: Session = Depends(get_db)):
    try:
        return response_module.register_peer_voip_token(db, params.uuid, params.voip_token)
    except HTTPException as e:
        return JSONResponse(content={"success": False, "error": str(e)}, status_code=e.status_code)
    except Exception as e:
        return JSONResponse(content={"success": False, "error": str(e)}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

# Presence: returns which of the supplied peer uuids are "reachable & available" — i.e. they have
# a live signaling socket (active_connections) AND are active (is_active = 1). The app uses this to
# drop both killed peers (socket gone within seconds) and peers who set themselves inactive, from
# everyone else's nearby list.
@app.post("/v1/peers_online/", dependencies=[Depends(verify_api_key), Depends(check_peer_uuid)])
async def peers_online(params: RequestPeersOnline, db: Session = Depends(get_db)):
    connected = [uid for uid in params.uuids if uid in manager.active_connections]
    # Single query → is_active for every queried peer. `online` = connected AND active; `inactive` =
    # is_active=0 (reported separately so the app keeps a backgrounded-but-active peer that's still nearby
    # while dropping a genuinely-inactive one even in BLE range).
    status = response_module.active_status(db, params.uuids)
    inactive = [h for h, active in status.items() if not active]
    online = [u for u in connected if status.get(u, False)]
    if online:
        # Drop peers this caller has blocked (or who blocked them) so they vanish from the nearby list.
        blocked = response_module.blocked_peer_set(db, params.uuid, online)
        online = [u for u in online if u not in blocked]
    return {"online": online, "inactive": inactive}

# Permanently blocks a peer for this user: marks (or creates) their user_user link is_active = 0, so
# the combination disappears from nearby + friends and can no longer wake either side. X-API-Key only.
@app.post("/v1/block_peer/", response_model=response_module.ResponseResult, dependencies=[Depends(verify_api_key), Depends(check_peer_uuid)])
async def block_peer(params: RequestBlockPeer, db: Session = Depends(get_db)):
    try:
        return response_module.block_peer(db, params.uuid, params.blocked_uuid)
    except HTTPException as e:
        return JSONResponse(content={"success": False, "error": str(e)}, status_code=e.status_code)
    except Exception as e:
        return JSONResponse(content={"success": False, "error": str(e)}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

# Marks friend_uuid as a friend of uuid (inserts a link into user_user). X-API-Key only.
@app.post("/v1/add_friend/", response_model=response_module.ResponseResult, dependencies=[Depends(verify_api_key), Depends(check_peer_uuid)])
async def add_friend(params: RequestAddFriend, db: Session = Depends(get_db)):
    try:
        return response_module.add_friend(db, params.uuid, params.friend_uuid)
    except HTTPException as e:
        return JSONResponse(content={"success": False, "error": str(e)}, status_code=e.status_code)
    except Exception as e:
        return JSONResponse(content={"success": False, "error": str(e)}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

# Ends the friendship between uuid and friend_uuid (removes the user_user link). X-API-Key only.
@app.post("/v1/cancel_friend/", response_model=response_module.ResponseResult, dependencies=[Depends(verify_api_key), Depends(check_peer_uuid)])
async def cancel_friend(params: RequestAddFriend, db: Session = Depends(get_db)):
    try:
        return response_module.cancel_friend(db, params.uuid, params.friend_uuid)
    except HTTPException as e:
        return JSONResponse(content={"success": False, "error": str(e)}, status_code=e.status_code)
    except Exception as e:
        return JSONResponse(content={"success": False, "error": str(e)}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

# Sets the user's active/inactive flag (is_active). X-API-Key only.
@app.post("/v1/activate_user/", response_model=response_module.ResponseResult, dependencies=[Depends(verify_api_key), Depends(check_peer_uuid)])
async def activate_user(params: RequestActivateUser, db: Session = Depends(get_db)):
    try:
        return response_module.activate_user(db, params.uuid, params.is_active)
    except HTTPException as e:
        return JSONResponse(content={"success": False, "error": str(e)}, status_code=e.status_code)
    except Exception as e:
        return JSONResponse(content={"success": False, "error": str(e)}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

# Vends WebRTC ICE servers: a public STUN plus short-lived TURN credentials derived from the
# license-issued TURN_SECRET (coturn use-auth-secret REST scheme: username = expiry unix time,
# credential = base64(HMAC-SHA1(secret, username))). Fetched once per call; STUN-only if TURN
# isn't configured. X-API-Key only.
@app.post("/v1/turn_credentials/", dependencies=[Depends(verify_api_key), Depends(check_peer_uuid)])
async def turn_credentials(params: RequestUuid):
    ice_servers = [{"urls": ["stun:stun.l.google.com:19302"]}]
    try:
        secret = license_manager.constants.get("TURN_SECRET", "")
        urls = license_manager.constants.get("TURN_URLS", [])
        if secret and urls:
            ttl = 3600  # credentials valid for 1 hour
            username = str(int(time.time()) + ttl)
            digest = hmac.new(secret.encode("utf-8"), username.encode("utf-8"), hashlib.sha1).digest()
            credential = base64.b64encode(digest).decode("ascii")
            ice_servers.append({"urls": urls, "username": username, "credential": credential})
    except Exception as e:
        print(f"turn_credentials error: {e}")
    return {"ice_servers": ice_servers}

# Returns all of the user's friends (nearby or not) with their profile + image, as {"friends": [...]}.
@app.post("/v1/friends/", dependencies=[Depends(verify_api_key), Depends(check_peer_uuid)])
async def get_friends(params: RequestId, db: Session = Depends(get_db)):
    try:
        friends = response_module.get_friends(db, params.uuid)
        for f in friends:
            file_path = os.path.join(PROFILE_DIR, f"peer_{f['uuid']}.jpg")
            if os.path.exists(file_path):
                with open(file_path, "rb") as fh:
                    f["image_data"] = base64.b64encode(fh.read()).decode("ascii")
        return {"friends": friends}
    except HTTPException as e:
        return JSONResponse(content={"success": False, "error": str(e)}, status_code=e.status_code)
    except Exception as e:
        return JSONResponse(content={"success": False, "error": str(e)}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

# Launch check: tells the app whether the backend still knows this peer uuid. Deliberately does
# NOT use check_peer_uuid — an unknown peer must get a 200 {"exists": false} (so the app can route
# to Create Profile) rather than a 403 the client would confuse with a network failure. Existence
# ignores is_active so an inactive (invisible) user isn't wrongly bounced to onboarding.
@app.post("/v1/check_peer/", dependencies=[Depends(verify_api_key)])
async def check_peer(params: RequestUuid, db: Session = Depends(get_db)):
    return {"exists": response_module.peer_exists(db, params.uuid)}

# Endpoint to look up a peer by its hex uuid. The uuid is supplied in the JSON body
# ({"uuid": ...}) so the iOS app reuses its standard postRequestForJson helper
# (X-API-Key, no OAuth), like the other peer calls.
@app.post("/v1/peer/", response_model=response_module.ResponsePeer, dependencies=[Depends(verify_api_key), Depends(check_peer_uuid)])
async def get_peer_post(params: RequestPeerLookup, db: Session = Depends(get_db)):
    try:
        response = response_module.get_peer(db, params.uuid)

        # Attach the profile image (saved as peer_{uuid_hex}.jpg by create_peer)
        # as a base64 string, mirroring how it is supplied on creation.
        file_path = os.path.join(PROFILE_DIR, f"peer_{params.uuid}.jpg")
        if os.path.exists(file_path):
            with open(file_path, "rb") as f:
                response.image_data = base64.b64encode(f.read()).decode("ascii")

        return response

    except HTTPException as e:
        return JSONResponse(content={"success": False, "error": str(e)}, status_code=e.status_code)
    except Exception as e:
        return JSONResponse(content={"success": False, "error": str(e)}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

# PUBLIC (no API key / no caller uuid): the WhatsApp-invite landing page on peers.club fetches the
# inviter's name to personalise itself ("<name> invited you to PEERS.CLUB"). A not-yet-installed
# visitor has no peer id, so this can't use the authenticated /v1/peer/ lookup. Only a name is
# returned, keyed by a random 128-bit uuid (not enumerable). The Access-Control-Allow-Origin header
# lets the peers.club page read it cross-origin (simple GET → no preflight needed).
@app.get("/v1/invite_info/{uuid}")
async def invite_info(uuid: str, response: fastapi.Response, db: Session = Depends(get_db)):
    response.headers["Access-Control-Allow-Origin"] = "*"
    name = response_module.get_peer_name(db, uuid)
    # Profile image (base64 JPEG), same source as /v1/peer/. Only read it when the name resolved —
    # which means get_peer_name validated `uuid` as proper hex, so the f"peer_{uuid}.jpg" path is safe.
    image_data = ""
    if name is not None:
        file_path = os.path.join(PROFILE_DIR, f"peer_{uuid}.jpg")
        if os.path.exists(file_path):
            with open(file_path, "rb") as f:
                image_data = base64.b64encode(f.read()).decode("ascii")
    return {"success": name is not None, "name": name or "", "image_data": image_data}

# Endpoint to update an existing peer. The peer is identified by its hex uuid in the
# JSON body; name, about_me and image_data are all optional so callers can update only
# the fields they supply (same iOS postRequestForJson helper as the other peer calls).
@app.post("/v1/update_peer/", response_model=response_module.ResponsePeer, dependencies=[Depends(verify_api_key), Depends(check_peer_uuid)])
async def update_peer(params: RequestUpdatePeer, db: Session = Depends(get_db)):
    message = ""
    result = False
    peer_hex = params.uuid
    try:
        if params.image_data:
            try:
                # Overwrite the existing profile image (peer_{uuid_hex}.jpg).
                filename = f"peer_{peer_hex}.jpg"
                file_path = os.path.join(PROFILE_DIR, filename)

                img_bytes = base64.b64decode(params.image_data)
                with open(file_path, "wb") as f:
                    f.write(img_bytes)

                image_filename = filename
                message = image_filename

            except Exception as img_err:
                message = f"Image save failed: {img_err}"
                image_filename = ""

        response = response_module.update_peer(db, peer_hex, params.name, params.about_me)

        # Return the stored profile image alongside the updated fields, mirroring get_peer.
        file_path = os.path.join(PROFILE_DIR, f"peer_{peer_hex}.jpg")
        if os.path.exists(file_path):
            with open(file_path, "rb") as f:
                response.image_data = base64.b64encode(f.read()).decode("ascii")

        result = True
        return response

    except HTTPException as e:
        return JSONResponse(content={"success": False, "error": str(e)}, status_code=e.status_code)
    except Exception as e:
        return JSONResponse(content={"success": False, "error": str(e)}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
    finally:
        message = message.replace("Exception error: ", "")
        # No peripheral involved in a peer update; log against the peer's hex uuid.
        response_module.log_online_action(db, "", peer_hex, 0, result, "", -1, message)

# Endpoint to update only a peer's profile image. The peer is identified by its hex
# uuid; image_data is the base64 image to store as peer_{uuid_hex}.jpg.
@app.post("/v1/update_peer_image/", response_model=response_module.ResponsePeer, dependencies=[Depends(verify_api_key), Depends(check_peer_uuid)])
async def update_peer_image(params: RequestUpdatePeerImage, db: Session = Depends(get_db)):
    message = ""
    result = False
    peer_hex = params.uuid
    try:
        # Confirm the peer exists (and load its current fields) before writing the image.
        response = response_module.get_peer(db, peer_hex)

        try:
            # Overwrite the existing profile image (peer_{uuid_hex}.jpg).
            filename = f"peer_{peer_hex}.jpg"
            file_path = os.path.join(PROFILE_DIR, filename)

            img_bytes = base64.b64decode(params.image_data)
            with open(file_path, "wb") as f:
                f.write(img_bytes)

            image_filename = filename
            message = image_filename

        except Exception as img_err:
            message = f"Image save failed: {img_err}"
            image_filename = ""

        # Return the stored profile image alongside the peer fields, mirroring get_peer.
        file_path = os.path.join(PROFILE_DIR, f"peer_{peer_hex}.jpg")
        if os.path.exists(file_path):
            with open(file_path, "rb") as f:
                response.image_data = base64.b64encode(f.read()).decode("ascii")

        result = True
        return response

    except HTTPException as e:
        return JSONResponse(content={"success": False, "error": str(e)}, status_code=e.status_code)
    except Exception as e:
        return JSONResponse(content={"success": False, "error": str(e)}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
    finally:
        message = message.replace("Exception error: ", "")
        # No peripheral involved in a peer update; log against the peer's hex uuid.
        response_module.log_online_action(db, "", peer_hex, 0, result, "", -1, message)

# --- Additional "about me" images -------------------------------------------------------------------
# Stored as static/additional_images/<uuid>-<seq>.jpg; user.image_order holds the in-use sequence numbers
# in display order (comma-separated). A new photo's seq = max(image_order)+1 (0 when empty), so a filename
# is never reused while still referenced. All POST; the modifying ones authenticate the owner via `uuid`,
# peer_images authenticates the requester via `caller_uuid`.

def _additional_image_path(peer_hex: str, seq: int) -> str:
    return os.path.join(ADDITIONAL_DIR, f"{peer_hex}-{seq}.jpg")

@app.post("/v1/add_image/", dependencies=[Depends(verify_api_key), Depends(check_peer_uuid)])
async def add_image(params: RequestAddImage, db: Session = Depends(get_db)):
    peer_hex = params.uuid
    try:
        order = response_module.get_image_order(db, peer_hex)
        if len(order) >= MAX_ADDITIONAL_IMAGES:
            return JSONResponse(content={"success": False, "error": "Image limit reached"}, status_code=400)
        new_seq = (max(order) + 1) if order else 0
        with open(_additional_image_path(peer_hex, new_seq), "wb") as f:
            f.write(base64.b64decode(params.image_data))
        pos = max(0, min(params.order_no, len(order)))
        order.insert(pos, new_seq)
        response_module.set_image_order(db, peer_hex, order)
        return {"success": True, "order": order, "seq": new_seq, "error": ""}
    except Exception as e:
        return JSONResponse(content={"success": False, "error": str(e)}, status_code=500)

@app.post("/v1/update_image/", dependencies=[Depends(verify_api_key), Depends(check_peer_uuid)])
async def update_image(params: RequestUpdateImage, db: Session = Depends(get_db)):
    peer_hex = params.uuid
    try:
        order = response_module.get_image_order(db, peer_hex)
        if params.order_no < 0 or params.order_no >= len(order):
            return JSONResponse(content={"success": False, "error": "Invalid order_no"}, status_code=400)
        seq = order[params.order_no]
        with open(_additional_image_path(peer_hex, seq), "wb") as f:
            f.write(base64.b64decode(params.image_data))
        return {"success": True, "order": order, "error": ""}
    except Exception as e:
        return JSONResponse(content={"success": False, "error": str(e)}, status_code=500)

@app.post("/v1/update_image_order/", dependencies=[Depends(verify_api_key), Depends(check_peer_uuid)])
async def update_image_order(params: RequestUpdateImageOrder, db: Session = Depends(get_db)):
    peer_hex = params.uuid
    try:
        order = response_module.get_image_order(db, peer_hex)
        try:
            positions = [int(p) for p in params.new_order.split(",") if p.strip() != ""]
        except ValueError:
            return JSONResponse(content={"success": False, "error": "Invalid order string"}, status_code=400)
        # Must be a permutation of the current positions (0…N-1) — reorder, never add/drop.
        if sorted(positions) != list(range(len(order))):
            return JSONResponse(content={"success": False, "error": "Order must be a permutation of current positions"}, status_code=400)
        new_order = [order[p] for p in positions]
        response_module.set_image_order(db, peer_hex, new_order)
        return {"success": True, "order": new_order, "error": ""}
    except Exception as e:
        return JSONResponse(content={"success": False, "error": str(e)}, status_code=500)

@app.post("/v1/delete_image/", dependencies=[Depends(verify_api_key), Depends(check_peer_uuid)])
async def delete_image(params: RequestDeleteImage, db: Session = Depends(get_db)):
    peer_hex = params.uuid
    try:
        order = response_module.get_image_order(db, peer_hex)
        if params.order_no < 0 or params.order_no >= len(order):
            return JSONResponse(content={"success": False, "error": "Invalid order_no"}, status_code=400)
        seq = order.pop(params.order_no)
        path = _additional_image_path(peer_hex, seq)
        if os.path.exists(path):
            os.remove(path)
        response_module.set_image_order(db, peer_hex, order)
        return {"success": True, "order": order, "error": ""}
    except Exception as e:
        return JSONResponse(content={"success": False, "error": str(e)}, status_code=500)

@app.post("/v1/peer_images/", dependencies=[Depends(verify_api_key), Depends(check_peer_uuid)])
async def peer_images(params: RequestPeerImages, db: Session = Depends(get_db)):
    peer_hex = params.uuid
    try:
        order = response_module.get_image_order(db, peer_hex)
        images = []
        for seq in order:
            path = _additional_image_path(peer_hex, seq)
            if os.path.exists(path):
                with open(path, "rb") as f:
                    images.append(base64.b64encode(f.read()).decode("ascii"))
        return {"success": True, "images": images, "error": ""}
    except Exception as e:
        return JSONResponse(content={"success": False, "error": str(e)}, status_code=500)

# Endpoint to update only a peer's name. The peer is identified by its hex uuid.
@app.post("/v1/update_peer_name/", response_model=response_module.ResponsePeer, dependencies=[Depends(verify_api_key), Depends(check_peer_uuid)])
async def update_peer_name(params: RequestUpdatePeerName, db: Session = Depends(get_db)):
    message = ""
    result = False
    peer_hex = params.uuid
    try:
        response = response_module.update_peer(db, peer_hex, name=params.name)

        # Return the stored profile image alongside the updated fields, mirroring get_peer.
        file_path = os.path.join(PROFILE_DIR, f"peer_{peer_hex}.jpg")
        if os.path.exists(file_path):
            with open(file_path, "rb") as f:
                response.image_data = base64.b64encode(f.read()).decode("ascii")

        result = True
        return response

    except HTTPException as e:
        return JSONResponse(content={"success": False, "error": str(e)}, status_code=e.status_code)
    except Exception as e:
        return JSONResponse(content={"success": False, "error": str(e)}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
    finally:
        message = message.replace("Exception error: ", "")
        # No peripheral involved in a peer update; log against the peer's hex uuid.
        response_module.log_online_action(db, "", peer_hex, 0, result, "", -1, message)

# Endpoint to update only a peer's about_me. The peer is identified by its hex uuid.
@app.post("/v1/update_peer_about_me/", response_model=response_module.ResponsePeer, dependencies=[Depends(verify_api_key), Depends(check_peer_uuid)])
async def update_peer_about_me(params: RequestUpdatePeerAboutMe, db: Session = Depends(get_db)):
    message = ""
    result = False
    peer_hex = params.uuid
    try:
        response = response_module.update_peer(db, peer_hex, about_me=params.about_me)

        # Return the stored profile image alongside the updated fields, mirroring get_peer.
        file_path = os.path.join(PROFILE_DIR, f"peer_{peer_hex}.jpg")
        if os.path.exists(file_path):
            with open(file_path, "rb") as f:
                response.image_data = base64.b64encode(f.read()).decode("ascii")

        result = True
        return response

    except HTTPException as e:
        return JSONResponse(content={"success": False, "error": str(e)}, status_code=e.status_code)
    except Exception as e:
        return JSONResponse(content={"success": False, "error": str(e)}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
    finally:
        message = message.replace("Exception error: ", "")
        # No peripheral involved in a peer update; log against the peer's hex uuid.
        response_module.log_online_action(db, "", peer_hex, 0, result, "", -1, message)

# Endpoint for login and 2FA token generation
@app.post("/v1/set_2fatoken/", response_model=response_module.ResponseResult, dependencies=[Depends(verify_api_key)])
async def login_and_set_2fatoken(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    try:
        response = response_module.set_2fatoken(db, form_data.username, form_data.password)
        # print(f"response Online Action: {response}")
        return response

    except HTTPException as e:
        return JSONResponse(content={"success": False, "error": str(e)}, status_code=e.status_code)
    except Exception as e:
        return JSONResponse(content={"success": False, "error": str(e)}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

# Endpoint for login
@app.post("/v1/login_no2fa/", response_model=response_module.ResponseResult, dependencies=[Depends(verify_api_key)])
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    try:
        response = response_module.login_no2fa(db, form_data.username, form_data.password)
        # print(f"response Online Action: {response}")
        return response

    except HTTPException as e:
        return JSONResponse(content={"success": False, "error": str(e)}, status_code=e.status_code)
    except Exception as e:
        return JSONResponse(content={"success": False, "error": str(e)}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

# Endpoint to verify the 2FA token
@app.post("/v1/verify_2fatoken/", response_model=response_module.ResponseToken, dependencies=[Depends(verify_api_key)])
async def verify_2fa(params: RequestVerify2FA, db: Session = Depends(get_db)):
    try:
        response = response_module.verify_2fatoken(db, params.email, params.token, params.uuid, license_manager.constants)
        # print(f"response Online Action: {response}")
        return response

    except HTTPException as e:
        return JSONResponse(content={"success": False, "error": str(e)}, status_code=e.status_code)
    except Exception as e:
        return JSONResponse(content={"success": False, "error": str(e)}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

# Endpoint to verify the 2FA token
@app.post("/v1/update_phone/", response_model=response_module.ResponseResult, dependencies=[Depends(verify_api_key)])
async def verify_2fa(params: RequestVerify2FA, username: response_module.ResponseUsername = Depends(check_credentials), db: Session = Depends(get_db)):
    try:
        if username:  # if creditential valid => email
            response = response_module.update_phone(db, params.email, params.token, params.uuid)
            # print(f"response Online Action: {response}")
            return response
        else:
            raise Exception(f"Exception error: Unauthorized")

    except HTTPException as e:
        return JSONResponse(content={"success": False, "error": str(e)}, status_code=e.status_code)
    except Exception as e:
        return JSONResponse(content={"success": False, "error": str(e)}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

# Endpoint for login and 2FA token generation
@app.post("/v1/set_password/", response_model=response_module.ResponseResult, dependencies=[Depends(verify_api_key)])
async def set_password(params: RequestPassword, db: Session = Depends(get_db)):
    try:
        response = response_module.set_password(db, params.email)
        # print(f"response Online Action: {response}")
        return response

    except HTTPException as e:
        return JSONResponse(content={"success": False, "error": str(e)}, status_code=e.status_code)
    except Exception as e:
        return JSONResponse(content={"success": False, "error": str(e)}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

@app.post("/v1/invite/", response_model=response_module.ResponseResult, dependencies=[Depends(verify_api_key)])
async def invite_user_for_lock(params: RequestInvite, username: response_module.ResponseUsername = Depends(check_credentials), db: Session = Depends(get_db)):
    try:
        if username:  # if creditential valid => email
            user_id, response = response_module.set_user_for_lock(db, username.email, params.email, params.ble_id, license_manager.constants, params.full_name, params.location, params.valid_from, params.valid_to, params.offline_support, params.remote_support, params.admin_support, params.send_keys, params.email_support)
            # print(f"response Online Action: {response}")
            response_module.log_online_action(db, params.ble_id, params.uuid, 5, True, "", user_id, params.email + " | " + params.full_name + " | " + params.location)
            return response
        else:
            raise Exception(f"Exception error: Unauthorized")

    except HTTPException as e:
        return JSONResponse(content={"success": False, "error": str(e)}, status_code=e.status_code)
    except Exception as e:
        return JSONResponse(content={"success": False, "error": str(e)}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

@app.post("/v1/get_pw_link/", response_model=response_module.ResponseShareLink, dependencies=[Depends(verify_api_key)])
async def request_password_link(params: RequestPassword, db: Session = Depends(get_db)):
    result = False
    try:
        response = response_module.get_password_link(db, params.email)
        # print(f"response Open Remote RESULT: {result}")
        if response:
            return response
        else:
            message = "No link provided"
            return JSONResponse(content={"success": result, "error": message}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
    except Exception as e:
        message = str(e)
        return JSONResponse(content={"success": result, "error": message}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
    # finally:
    #     message = message.replace("Exception error: ", "")
        # response_module.log_online_action(params.ble_id, params.uuid, 4, result, params.link_id, -1, message)

@app.post("/v1/license/", response_model=response_module.ResponseLicense, dependencies=[Depends(verify_api_key)])
async def get_license(params: RequestId, username: response_module.ResponseUsername = Depends(check_credentials), db: Session = Depends(get_db)):
    try:
        if username: #if creditential valid => email
            if response_module.check_is_super_admin(db, username.email):  # if creditential valid => email
                license_manager.renew_license()
                response = response_module.ResponseLicense(usage_users=license_manager.usage_users, usage_keys=license_manager.usage_keys, usage_peripherals=license_manager.usage_peripherals, license_users=license_manager.constants["LICENSE_USERS"], license_keys=license_manager.constants["LICENSE_KEYS"], license_peripherals=license_manager.constants["LICENSE_PERIPHERALS"], license_expiry_date=license_manager.constants["LICENSE_EXPIRY_DATE"])
                # print(f"response Remote: {response}")
                return response

        raise Exception(f"Exception error: Unauthorized")

    except Exception as e:
        return JSONResponse(content={"success": False, "error": str(e)}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

@app.post("/v1/peripheral/", response_model=dict, dependencies=[Depends(verify_api_key)])
async def get_peripheral(params: RequestPeripheral, username: response_module.ResponseUsername = Depends(check_credentials), db: Session = Depends(get_db)):
    try:
        if username: #if credituser.getPeripheralName()ential valid => email
            if response_module.check_is_super_admin(db, username.email):  # if creditential valid => email
                row = response_module.get_peripheral(db, params.user_id, params.ble_id)
                response = JSONResponse(content=dict(row), status_code=status.HTTP_200_OK)
                # print(f"response Remote: {response}")
                return response

        raise Exception(f"Exception error: Unauthorized")

    except Exception as e:
        return JSONResponse(content={"success": False, "error": str(e)}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

@app.post("/v1/user/", response_model=dict, dependencies=[Depends(verify_api_key)])
async def get_user(params: RequestUser, username: response_module.ResponseUsername = Depends(check_credentials), db: Session = Depends(get_db)):
    try:
        if username: #if creditential valid => email
            if response_module.check_is_super_admin(db, username.email):  # if creditential valid => email
                row = response_module.get_user(db, params.user_id)
                response = JSONResponse(content=dict(row), status_code=status.HTTP_200_OK)
                # print(f"response Remote: {response}")
                return response

        raise Exception(f"Exception error: Unauthorized")

    except Exception as e:
        return JSONResponse(content={"success": False, "error": str(e)}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

# Endpoint for list users with OAuth2.0 (for super_admin only)
@app.post("/v1/users/", response_model=List[dict], dependencies=[Depends(verify_api_key)])
async def get_users(params: RequestUsers, username: response_module.ResponseUsername = Depends(check_credentials), db: Session = Depends(get_db)):
    try:
        if username: #if creditential valid => email
            # if response_module.check_is_super_admin(db, username.email):  # if creditential valid => email
            rows = response_module.get_users(db, params.user_id)
            #response = JSONResponse(content=rows, status_code=status.HTTP_200_OK)
            response = JSONResponse(content=[dict(row) for row in rows], status_code=status.HTTP_200_OK)
            # print(f"response Remote: {response}")
            return response

        raise Exception(f"Exception error: Unauthorized")

    except Exception as e:
        return JSONResponse(content={"success": False, "error": str(e)}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

# Endpoint for update user with OAuth2.0 (for super_admin only)
@app.post("/v1/update_user/", response_model=response_module.ResponseResult, dependencies=[Depends(verify_api_key)])
async def update_user(params: RequestSetUser, username: response_module.ResponseUsername = Depends(check_credentials), db: Session = Depends(get_db)):
    try:
        if username: #if creditential valid => email
            # if response_module.check_is_super_admin(db, username.email):  # if creditential valid => email
            first_name, last_name = response_module.split_name(params.full_name)
            response_module.update_user(db, params.id, params.email, first_name, last_name, params.location, params.super_admin_support)
            response_module.log_online_action(db, "", params.uuid, 6, True, "", params.id,
                                              params.email + " | " + params.full_name + " | " + params.location + " | " + str(params.super_admin_support))
            return response_module.ResponseResult(success=True, error="")

        raise Exception(f"Exception error: Unauthorized")

    except Exception as e:
        return JSONResponse(content={"success": False, "error": str(e)}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

# @app.post("/v1/activate_user/", response_model=response_module.ResponseResult, dependencies=[Depends(verify_api_key)])
# async def activate_user(params: RequestActivateUser, username: response_module.ResponseUsername = Depends(check_credentials), db: Session = Depends(get_db)):
#     try:
#         if username: #if creditential valid => email
#             if response_module.check_is_super_admin(db, username.email):
#                 response = response_module.activate_user(db, params.id, params.is_active)
#                 response_module.log_online_action(db, "", params.uuid, 13 if params.is_active else 14, True, "", params.id, "")
#                 return response
#
#         raise Exception(f"Exception error: Unauthorized")
#
#     except Exception as e:
#         return JSONResponse(content={"success": False, "error": str(e)}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

@app.post("/v1/add_user/", response_model=response_module.ResponseResult, dependencies=[Depends(verify_api_key)])
async def add_user(params: RequestAddUser, username: response_module.ResponseUsername = Depends(check_credentials), db: Session = Depends(get_db)):
    try:
        if username: #if creditential valid => email
            if response_module.check_is_super_admin(db, username.email):
                user_id, response = response_module.add_user_for_all_locks(db, username.email, params.email, params.full_name, params.location, params.super_admin_support, params.email_support)
                # print(f"response Online Action: {response}")
                response_module.log_online_action(db, "", params.uuid, 17, True, "", user_id, params.email + " | " + params.full_name + " | " + params.location)
                return response

        raise Exception(f"Exception error: Unauthorized")

    except HTTPException as e:
        return JSONResponse(content={"success": False, "error": str(e)}, status_code=e.status_code)
    except Exception as e:
        return JSONResponse(content={"success": False, "error": str(e)}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

@app.post("/v1/set_user_lock/", response_model=response_module.ResponseResult, dependencies=[Depends(verify_api_key)])
async def set_user_lock(params: RequestSetUserLock, username: response_module.ResponseUsername = Depends(check_credentials), db: Session = Depends(get_db)):
    try:
        if username: #if creditential valid => email
            # if response_module.check_is_super_admin(db, username.email):  # if creditential valid => email
            response_module.set_user_lock(db, params.user_id, username.email, params.ble_id, license_manager.constants, params.valid_from, params.valid_to, params.offline_support, params.remote_support, params.auto_unlock_support, params.admin_support, params.send_keys)
            response_module.log_online_action(db, "", params.uuid, 7, True, "", params.user_id,
                                              params.valid_from + " | " + params.valid_to + " | " + str(params.offline_support) + " | " + str(params.remote_support)  + " | " + str(params.auto_unlock_support)  + " | " + str(params.admin_support)  + " | " + str(params.send_keys))
            return response_module.ResponseResult(success=True, error="")

        raise Exception(f"Exception error: Unauthorized")

    except Exception as e:
        return JSONResponse(content={"success": False, "error": str(e)}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

@app.post("/v1/activate_user_lock/", response_model=response_module.ResponseResult, dependencies=[Depends(verify_api_key)])
async def activate_user(params: RequestActivateUserLock, username: response_module.ResponseUsername = Depends(check_credentials), db: Session = Depends(get_db)):
    try:
        if username: #if creditential valid => email
            # if response_module.check_is_super_admin(db, username.email):
                response = response_module.activate_user_lock(db, params.id, params.ble_id, params.is_active)
                response_module.log_online_action(db, params.ble_id, params.uuid, 15 if params.is_active else 16, True, "", params.id, "")
                return response

        raise Exception(f"Exception error: Unauthorized")

    except Exception as e:
        return JSONResponse(content={"success": False, "error": str(e)}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

@app.post("/v1/set_lock/", response_model=response_module.ResponseResult, dependencies=[Depends(verify_api_key)])
async def set_lock(params: RequestSetLock, username: response_module.ResponseUsername = Depends(check_credentials), db: Session = Depends(get_db)):
    try:
        if username:  # if creditential valid => email
            if response_module.check_is_super_admin(db, username.email):  # if creditential valid => email
                response_module.set_peripheral(db, params.ble_id, params.name, params.location, params.sig_duration, params.auto_unlock_db, params.remote_support, params.is_active, params.apply_remote_support_to_all_users, params.apply_active_to_all_users)
                response_module.log_online_action(db, params.ble_id, params.uuid, 10, True, "", -1, params.name + " | " + params.location + " | " + str(params.sig_duration) + " | " + str(params.auto_unlock_db) + " | " + str(params.remote_support) + " | " + str(params.is_active) + " | " + str(params.apply_remote_support_to_all_users) + " | " + str(params.apply_active_to_all_users))
                return response_module.ResponseResult(success=True, error="")

        raise Exception(f"Exception error: Unauthorized")

    except Exception as e:
        return JSONResponse(content={"success": False, "error": str(e)}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

@app.post("/v1/delete_lock/", response_model=response_module.ResponseResult, dependencies=[Depends(verify_api_key)])
async def delete_lock(params: RequestUuIdBleId, username: response_module.ResponseUsername = Depends(check_credentials), db: Session = Depends(get_db)):
    try:
        if username:  # if creditential valid => email
            if response_module.check_is_super_admin(db, username.email):  # if creditential valid => email
                # Log before otherwise log cannot find peripheral anymore
                response_module.log_online_action(db, params.ble_id, params.uuid, 11, True, "", -1, "" )
                response_module.delete_peripheral(db, params.ble_id)
                return response_module.ResponseResult(success=True, error="")

        raise Exception(f"Exception error: Unauthorized")

    except Exception as e:
        return JSONResponse(content={"success": False, "error": str(e)}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

@app.post("/v1/delete_user/", response_model=response_module.ResponseResult, dependencies=[Depends(verify_api_key)])
async def delete_user(params: RequestUuIdId, username: response_module.ResponseUsername = Depends(check_credentials), db: Session = Depends(get_db)):
    try:
        if username:  # if creditential valid => email
            if response_module.check_is_super_admin(db, username.email):  # if creditential valid => super admin
                # Log before otherwise log cannot find user anymore
                response_module.log_online_action(db, "", params.uuid, 12, True, "", params.id, "" )
                response_module.delete_user(db, params.id)
                return response_module.ResponseResult(success=True, error="")

        raise Exception(f"Exception error: Unauthorized")

    except Exception as e:
        return JSONResponse(content={"success": False, "error": str(e)}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

@app.post("/v1/authenticate/", response_model=response_module.ResponseToken, dependencies=[Depends(verify_api_key)])
async def authenticate(form_data: OAuth2PasswordRequestForm = Depends(), uuid: str | None = fastapi.Form(None), db: Session = Depends(get_db)):
    try:
        response = response_module.login_panel(db, form_data.username, form_data.password, uuid, license_manager.constants)
        # print(f"response Online Action: {response}")
        return response

    except HTTPException as e:
        return JSONResponse(content={"success": False, "error": str(e)}, status_code=e.status_code)
    except Exception as e:
        return JSONResponse(content={"success": False, "error": str(e)}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

@app.post("/v1/bell_panel/", response_model=List[dict], dependencies=[Depends(verify_api_key)])
async def get_bell_panel(params: RequestId, username: response_module.ResponseUsername = Depends(check_credentials), db: Session = Depends(get_db)):
    try:
        if username: #if creditential valid => email
            user_id = response_module.check_is_bell_panel(db, username.email)["id"]
            if user_id is not None:  # if creditential valid => bell panel
                rows = response_module.get_bell_panel(db, user_id)
                #response = JSONResponse(content=rows, status_code=status.HTTP_200_OK)
                response = JSONResponse(content=[dict(row) for row in rows], status_code=status.HTTP_200_OK)
                # print(f"response Remote: {response}")
                return response

        raise Exception(f"Exception error: Unauthorized")

    except Exception as e:
        return JSONResponse(content={"success": False, "error": str(e)}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

@app.post("/v1/fcm_token/", response_model=response_module.ResponseResult, dependencies=[Depends(verify_api_key)])
async def store_fcm_token(params: RequestStoreFCMToken, username: response_module.ResponseUsername = Depends(check_credentials), db: Session = Depends(get_db)):
    try:
        if username:  # if creditential valid => email
            # user_id = response_module.check_is_bell_panel(db, username.email)["id"]
            user_id = response_module.check_user_exists(db, username.email)["id"]
            if user_id is not None:
                response_module.store_fcm_token(db, user_id, params.fcm_token)
                return response_module.ResponseResult(success=True, error="")

        raise Exception(f"Exception error: Unauthorized")

    except Exception as e:
        return JSONResponse(content={"success": False, "error": str(e)}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

@app.post("/v1/open_bellxs/", response_model=response_module.ResponseResult, dependencies=[Depends(verify_api_key)])
async def open_bellxs_lock(params: RequestOpenBellXS,  username: response_module.ResponseUsername = Depends(check_credentials), db: Session = Depends(get_db)):
    result:bool = False
    message:str = ""
    try:
        if username: #if creditential valid => email
            if not isinstance(db, Session):
                db = Database(license_manager.constants["DATABASE_URL"]).create_session()
            result = response_module.open_bellxs_lock(db, params.ble_id, username.email)
            return response_module.ResponseResult(success=result, error="")
        else:
            raise Exception(f"Exception error: Unauthorized")

    except HTTPException as e:
        message = str(e)
        return JSONResponse(content={"success": False, "error": str(e)}, status_code=e.status_code)
    except Exception as e:
        message = str(e)
        return JSONResponse(content={"success": False, "error": message}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
    finally:
        message = message.replace("Exception error: ", "")
        response_module.log_online_action(db, params.ble_id, params.uuid, 21, result, "", -1, message)

@app.post("/v1/notify_doorbell/", response_model=response_module.ResponseResult, dependencies=[Depends(verify_api_key)])
async def notify_safexs_doorbell(params: RequestNotifySafeXS,  username: response_module.ResponseUsername = Depends(check_credentials), db: Session = Depends(get_db)):
    result:bool = False
    message:str = ""
    ble_id = ""
    image_filename = ""  # We use to store the filename, e.g., "snap_12345_1.jpg"

    try:
        if username: # if creditential valid => email
            user_id = response_module.check_is_bell_panel(db, username.email)["id"]
            if user_id is not None:
                # Process image
                if params.image_data:
                    try:
                        # 1. Create the specific filename requested
                        # snap_{timestamp}_{bell_id}.jpg
                        filename = f"snap_{int(time.time())}_{params.bell_id}.jpg"
                        file_path = os.path.join(SNAPSHOT_DIR, filename)

                        # 2. Decode and Save locally
                        img_bytes = base64.b64decode(params.image_data)
                        with open(file_path, "wb") as f:
                            f.write(img_bytes)

                        # 3. Store the filename to send in notification
                        image_filename = filename
                        message = image_filename

                    except Exception as img_err:
                        message = f"Image save failed: {img_err}"
                        image_filename = ""

                ble_id = response_module.notify_safexs_doorbell(db, params.bell_id, image_filename)
                result = True
                return response_module.ResponseResult(success=True, error="")

        raise Exception(f"Exception error: Unauthorized")

    except Exception as e:
        message = str(e)
        return JSONResponse(content={"success": False, "error": message}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
    finally:
        message = message.replace("Exception error: ", "")
        response_module.log_online_action(db, ble_id, params.uuid, 22, result, "", -1, message)

@app.post("/v1/stop_doorbell/", response_model=response_module.ResponseResult, dependencies=[Depends(verify_api_key)])
async def stop_safexs_doorbell(params: RequestNotifySafeXS,  username: response_module.ResponseUsername = Depends(check_credentials), db: Session = Depends(get_db)):
    result:bool = False
    message:str = ""
    ble_id = ""
    image_filename = ""  # We use to store the filename, e.g., "snap_12345_1.jpg"

    try:
        if username: # if creditential valid => email
            user_id = response_module.check_is_bell_panel(db, username.email)["id"]
            if user_id is not None:
                ble_id = response_module.stop_safexs_doorbell_ring(db, params.bell_id)
                result = True
                return response_module.ResponseResult(success=True, error="")

        raise Exception(f"Exception error: Unauthorized")

    except Exception as e:
        message = str(e)
        return JSONResponse(content={"success": False, "error": message}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
    finally:
        message = message.replace("Exception error: ", "")
        response_module.log_online_action(db, ble_id, params.uuid, 23, result, "", -1, message)



@app.post("/v1/peer_image/", response_model=response_module.ResponseImage, dependencies=[Depends(verify_api_key)])
async def post_peer_image(params: RequestGetImage, db: Session = Depends(get_db)):
    """
    Retrieves the image file, converts it to Base64, and returns it in JSON.
    """
    # 1. Verify Authentication
    # if not username:
    #     raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

    # 2. Security Check (Directory Traversal)
    filename = params.image_filename
    if ".." in filename or "/" in filename or "\\" in filename:
        return response_module.ResponseImage(success=False, image_data="", error="Invalid filename")

    # 3. Construct path
    file_path = os.path.join("static/profile_images", filename)

    # 4. Read File and Encode
    if os.path.exists(file_path):
        try:
            with open(file_path, "rb") as image_file:
                # Read binary data and encode to Base64 string
                encoded_string = base64.b64encode(image_file.read()).decode('utf-8')

            return response_module.ResponseImage(success=True, image_data=encoded_string, error="")

        except Exception as e:
            # Handle read errors
            return response_module.ResponseImage(success=False, image_data="", error=f"Error reading file: {str(e)}")
    else:
        return response_module.ResponseImage(success=False, image_data="", error="Image not found")

@app.post("/v1/probe/", response_model=response_module.ResponseResult, dependencies=[Depends(verify_api_key)])
async def delete_user(params: RequestId, username: response_module.ResponseUsername = Depends(check_credentials), db: Session = Depends(get_db)):
    try:
        if username:  # if creditential valid => email
            return response_module.ResponseResult(success=True, error="")

        raise Exception(f"Exception error: Unauthorized")

    except Exception as e:
        return JSONResponse(content={"success": False, "error": str(e)}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

