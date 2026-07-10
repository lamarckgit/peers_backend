import secrets
import uuid

from functions.BLE_module import handle_open
from crypt_class import SafeXSCrypt
from functions import crypt_module
from helpers.email_templates import *
#from constants import Constants

from datetime import datetime
from fastapi import HTTPException, status
from pydantic import BaseModel
import random
from sqlalchemy.orm import Session
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
import string
import time
import os
import httpx
import jwt
import firebase_admin
from firebase_admin import credentials, messaging

# BellXS / SafeXS Firebase apps are unused in this peers-only deployment. Their service-account
# JSONs have been removed; the inherited lock/doorbell push helpers (open_bellxs_lock /
# notify_safexs_doorbell / stop_safexs_doorbell_ring) are left importable but inert — they
# early-return when their app is None. Only the PEERS.CLUB app below is actually used.
app_bellxs = None
app_safexs = None

# --- Initialize PEERS.CLUB (used to push INCOMING_CHAT to a backgrounded peer) ---
# Sending FCM to the peers.club iOS app (Firebase project "peers-club") requires THAT project's
# own service-account key. Drop serviceAccountKeyPeersClub.json next to the other two. When it's
# absent, background chat push is simply disabled — foreground chat over the WS relay still works.
app_peers = None
try:
    cred_peers = credentials.Certificate("serviceAccountKeyPeersClub.json")
    app_peers = firebase_admin.initialize_app(cred_peers, name='peers_app')
    print("PEERS.CLUB Firebase app initialized successfully.")
except (FileNotFoundError, IOError):
    print("PEERS.CLUB service account 'serviceAccountKeyPeersClub.json' not found — "
          "background chat push disabled (foreground chat still works).")
except ValueError:
    print("PEERS.CLUB Firebase app already initialized.")

class ResponseCreatePeer(BaseModel):
    success: bool
    uuid: str
    peer_name: str = ""        # 6-char public peer code (others use it to send a friend request)
    error: str

class ResponsePeer(BaseModel):
    success: bool
    uuid: str
    name: str
    about_me: str
    peer_name: str = ""        # 6-char public peer code shown under the profile picture
    image_data: str = None
    error: str

class ResponseBLE(BaseModel):
    phone_id: str
    ble_id: str
    name: str
    location: str
    auto_unlock_db: int
    auto_unlock: bool
    offline_support: bool
    is_admin: bool
    is_super_admin: bool
    payload: str
    payload_offline: str
    seed: str
    totp_secret: str
    public_key: str

class ResponseImage(BaseModel):
    success: bool
    image_data: str  # This will hold the huge Base64 string
    error: str = ""

class ResponseLicense(BaseModel):
    usage_users: int
    usage_keys: int
    usage_peripherals: int
    license_users: int
    license_keys: int
    license_peripherals: int
    license_expiry_date: str

class ResponseOpenOnline(BaseModel):
    payload: str

# class ResponseRemote(BaseModel):
#     ble_id: str
#     name: str
#     location: str
#     last_temperature: int
#     is_admin: bool
#     num_keys: int

class ResponseResult(BaseModel):
    success: bool
    error: str

class ResponseShare(BaseModel):
    uses_left: int
    success: bool
    error: str

class ResponseShareLink(BaseModel):
    link_id: str

class ResponseToken(BaseModel):
    access_token: str
    expire: datetime
    user_id: int
    super_admin: bool

class ResponseUsername(BaseModel):
    email: str

def get_online_payload(db: Session, ble_id, phone_uuid, constants: dict):
    payload = ""
    query = text("""
    SELECT p.sig_duration, p.auto_unlock_db, p.totp_secret, p.seed
    FROM peripheral p JOIN user_peripheral up ON p.ble_id = up.peripheral_ble_id  JOIN user u ON u.uuid = up.user_id
    WHERE p.ble_id = :ble_id
    AND u.phone_uuid = :phone_uuid
    AND (up.is_active = 1 AND p.is_active = 1
        AND (up.valid_from <= NOW() OR up.valid_from IS NULL) AND (NOW() <= up.valid_to OR up.valid_to IS NULL)
        OR up.is_admin = 1)
    """)
    try:
        result = db.execute(query, {"ble_id": ble_id, "phone_uuid": phone_uuid}).mappings().fetchone()
        if result:
            crypt_obj = SafeXSCrypt(result["seed"], result["totp_secret"], constants)
            payload = crypt_module.get_online_unlock(crypt_obj, int(time.time()), phone_uuid, result["sig_duration"])
            payload = crypt_module.encrypt(crypt_obj, payload)
        else:
            raise Exception(f"Key has exipired")

        return ResponseOpenOnline(payload=payload)

    except SQLAlchemyError as e:
        raise RuntimeError(f"Database error: {str(e)}")
    except Exception as e:
        raise Exception(f"Exception error: {str(e)}")

def get_nearby_properties(db: Session, ble_id, phone_uuid, constants: dict):
    print(f"Processing nearby properties for BLE ID: {ble_id}")
    if ble_id == "88B79F70-61E0-4884-9A88-383AD7590BC6":
        print(f"*** Processing nearby properties for MELANIE: {ble_id} ***")
    query = text(""" 
    SELECT ph.name, ph.uuid
    FROM phone ph 
    WHERE ph.uuid = :ble_id
    """)
    try:
        result = db.execute(query, {"ble_id": ble_id}).mappings().fetchone()
        open_online_cmd = ""  # crypto_client.encrypt(open_online_cmd) This has been implemented as a separate request see "open_online"
        if result:
            # open_offline_cmd = get_offline_payload(result["offline_support"], result["offline_support_from"], result["offline_support_to"], result["uuid"], result["sig_duration"], result["seed"], result["totp_secret"], constants)
            # Return response
            response = ResponseBLE(phone_id=phone_uuid, ble_id=ble_id, name=result["name"], location="", auto_unlock_db=-30, auto_unlock=False, offline_support=False, is_admin=False, is_super_admin=False, payload="", payload_offline="", seed="", totp_secret="", public_key="")
        else:
            # Return empty response if no data found
            response = ResponseBLE(phone_id=phone_uuid, ble_id=ble_id, name="", location="", auto_unlock_db=-30, auto_unlock=False, offline_support=False, is_admin=False, is_super_admin=False, payload="", payload_offline="", seed="", totp_secret="", public_key="")

        return response

    except ValueError as e:
        raise ValueError(f"Invalid date format: {e}")
    except SQLAlchemyError as e:
        raise RuntimeError(f"Database error: {str(e)}")
    except Exception as e:
        raise Exception(f"Exception error: {str(e)}")


def safe_datetime(dt):
    if isinstance(dt, datetime):
        return dt
    return datetime.now()

# Get Offline Payload
def get_offline_payload(offline_support: bool, offline_support_from: datetime, offline_support_to: datetime, phone_uuid: str, sig_duration: int, seed: str, totp_secret: str, constants: dict):
    # Check offline support
    if offline_support:
        # Process datetime fields
        if offline_support_from:
            date_db_from = offline_support_from
        else:
            # No time limit
            date_db_from = datetime.now()

        if offline_support_to:
            date_db_to = offline_support_to
        else:
            # No time limit
            date_string = "2036-01-19 03:14:07"  # official max. time 2036-01-19 03:14:07 for 32-bit Unix timestamp
            date_db_to = datetime.strptime(date_string, "%Y-%m-%d %H:%M:%S")

        date_object_from = safe_datetime(date_db_from)
        date_object_to = safe_datetime(date_db_to)
        # Encrypt offline unlock command
        open_offline_cmd = crypt_module.get_offline_unlock_with_timeslot(
            int(time.time()), int(date_object_from.timestamp()), int(date_object_to.timestamp()), phone_uuid, sig_duration
        )
        crypt_obj = SafeXSCrypt(seed, totp_secret, constants)
        open_offline_cmd = crypt_module.encrypt(crypt_obj, open_offline_cmd)[:-1]  # Remove `;` for offline
    else:
        open_offline_cmd = ""

    return open_offline_cmd

def log_online_action(db: Session, ble_id, uuid, action_id, is_success, link_id = "", user_id: int = -1, message = "", temperature = 99):
    peripheral_name = None
    try:
        if ble_id:
            # Fetch info lock, update temperature
            query = text("""
            SELECT p.name FROM peripheral p WHERE p.ble_id = :ble_id
            """)
            peripheral = db.execute(query, {"ble_id": ble_id}).mappings().fetchone()
            if peripheral:
                peripheral_name = peripheral["name"]
                if temperature < 99:
                    update_query = text("""
                    UPDATE peripheral SET last_temperature = :temperature WHERE ble_id = :ble_id
                    """)
                    db.execute(update_query,{"temperature": temperature, "ble_id": ble_id})
                    db.commit()
            else:
                raise Exception("Invalid request")
        # Fetch info user that performed action
        user_email = uuid if "@" in uuid else None
        if user_email:
            uuid = ""
        else:
            query = text("""
            SELECT u.email FROM user u WHERE u.phone_uuid = :uuid
            """)
            user = db.execute(query, {"uuid": uuid}).mappings().fetchone()
            if user:
                user_email = user["email"]
        # Fetch info user that is set (added, updated)
        if user_id < 0:
            user_email_set = ""
        else:
            query = text("""
            SELECT u.email FROM user u WHERE u.uuid = :user_id
            """)
            user_email_set = db.execute(query, {"user_id": user_id}).mappings().fetchone()["email"]
        # Fetch action name
        query = text("""
        SELECT at.name FROM action_type at WHERE at.id = :action_id
        """)
        action_name = db.execute(query, {"action_id": action_id}).mappings().fetchone()["name"]
        # Insert log record
        # current_timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')  # Trim microseconds to milliseconds
        insert_query = text("""
        INSERT INTO action_log (user_email, phone_uuid, peripheral_ble_id, peripheral_name, action_type_name, link_id, is_success, user_id, user_email_set, message) VALUES (:user_email, :uuid, :ble_id, :peripheral_name, :action_name, :link_id, :is_success, :user_id, :user_email_set, :message)
        """)
        db.execute(insert_query, {"user_email": user_email, "uuid":uuid, "ble_id": ble_id, "peripheral_name":peripheral_name, "action_name":action_name, "link_id": link_id, "is_success": is_success, "user_id": user_id, "user_email_set": user_email_set, "message": message})
        db.commit()

        return ResponseResult(success=True, error="")

    except SQLAlchemyError as e:
        raise RuntimeError(f"Database error: {str(e)}")
    except Exception as e:
        raise Exception(f"Exception error: {str(e)}")

def get_all_properties(db: Session, phone_uuid, constants: dict, is_active: bool = True):
    if is_active:
        query = text("""
SELECT 
    p.name, p.location, p.ble_id, p.sig_duration, p.auto_unlock_db, p.remote_support AS lock_remote, 
    /* --- START OF MODIFIED LOGIC --- */
    CASE 
        WHEN (
            -- Condition A: Matches logic of Query 1 (Active Bell User exists for this peripheral)
            EXISTS (
                SELECT 1 
                FROM peripheral_bell_user pbu 
                WHERE pbu.peripheral_ble_id = p.ble_id 
                AND pbu.is_active = 1
            )
            -- Condition B: Ensure the Phone Peripheral link exists (Enforced in Query 1 by the WHERE clause)
            AND pp.phone_uuid IS NOT NULL 
        ) THEN '1' 
        ELSE '0' 
    END AS doorbell_support,
    /* --- END OF MODIFIED LOGIC --- */
    p.is_active AS lock_is_active, p.last_temperature, ph.uuid AS phone_id, up.is_admin, up.num_keys, up.remote_support, up.offline_support, IFNULL(DATE_FORMAT(up.valid_to, '%Y-%m-%d %H:%i:%s'),'') AS valid_to, up.auto_unlock, p.seed, p.totp_secret, '' AS public_key, u.is_super_admin, u.location AS user_location, up.is_active
FROM user u
    LEFT JOIN user_peripheral up ON u.uuid = up.user_id
    LEFT JOIN phone_peripheral pp ON u.phone_uuid = pp.phone_uuid AND up.peripheral_ble_id = pp.peripheral_ble_id
    LEFT JOIN phone ph ON ph.uuid = u.phone_uuid
    LEFT JOIN peripheral p ON up.peripheral_ble_id = p.ble_id
WHERE UPPER(u.phone_uuid) = :phone_uuid
    AND p.is_active = 1
    AND (
        up.is_active = 1
        AND (up.valid_from <= NOW() OR up.valid_from IS NULL) 
        AND (NOW() <= up.valid_to OR up.valid_to IS NULL)
        OR up.is_admin = 1 
        OR u.is_super_admin = 1
    );
        """) # AND (up.num_keys > 1 OR up.remote_support = 1)
    else:
        query = text("""
SELECT 
    p.name, p.location, p.ble_id, p.sig_duration, p.auto_unlock_db, p.remote_support AS lock_remote, 
    /* --- START OF MODIFIED LOGIC --- */
    CASE 
        WHEN (
            -- Check if an active Bell User exists for this specific peripheral
            EXISTS (
                SELECT 1 
                FROM peripheral_bell_user pbu 
                    WHERE pbu.peripheral_ble_id = p.ble_id 
                AND pbu.is_active = 1
            )
            -- Check if the Phone Peripheral link exists (already joined as 'pp')
            AND pp.phone_uuid IS NOT NULL 
        ) THEN '1' 
        ELSE '0' 
    END AS doorbell_support,
    /* --- END OF MODIFIED LOGIC --- */
    p.is_active AS lock_is_active, p.last_temperature, ph.uuid AS phone_id, up.is_admin, up.num_keys, up.remote_support, up.offline_support, IFNULL(DATE_FORMAT(up.valid_to, '%Y-%m-%d %H:%i:%s'),'') AS valid_to, up.auto_unlock, p.seed, p.totp_secret, '' AS public_key, u.is_super_admin, u.location AS user_location, up.is_active
FROM user u
    LEFT JOIN user_peripheral up ON u.uuid = up.user_id
    LEFT JOIN phone_peripheral pp ON u.phone_uuid = pp.phone_uuid AND up.peripheral_ble_id = pp.peripheral_ble_id
    LEFT JOIN phone ph ON ph.uuid = u.phone_uuid
    LEFT JOIN peripheral p ON up.peripheral_ble_id = p.ble_id
WHERE p.is_active = 0 AND ph.uuid = :phone_uuid 
            """)
    try:
        # Fetch all
        rows = db.execute(query, {"phone_uuid": phone_uuid.upper()}).mappings().fetchall()
        # Add offline payload to each row
        rows_with_offline_cmd = []
        for row in rows:
            row_dict = dict(row)  # Make it mutable
            row_dict["payload_offline"] = get_offline_payload(row["offline_support"],row.get("offline_support_from"),row.get("offline_support_to"),row["phone_id"],row["sig_duration"],row["seed"],row["totp_secret"], constants)
            rows_with_offline_cmd.append(row_dict)

        return rows_with_offline_cmd

    except SQLAlchemyError as e:
        raise RuntimeError(f"Database error: {str(e)}")
    except Exception as e:
        raise Exception(f"Exception error: {str(e)}")

def set_share_link(db: Session, ble_id, phone_uuid, valid_from, valid_to, uses_limit, reference, constants: dict):
    query = text("""
    SELECT p.name FROM peripheral p WHERE p.ble_id = :ble_id
    """)
    try:
        # Fetch lock to open
        peripheral = db.execute(query, {"ble_id": ble_id}).mappings().fetchone()
        if peripheral:
            peripheral_name = peripheral["name"]
        else:
            raise Exception("Invalid request")
        # Fetch user that performs action open
        user_email = None
        query = text("""
        SELECT u.email FROM user u WHERE u.phone_uuid = :phone_uuid
        """)
        user = db.execute(query, {"phone_uuid": phone_uuid}).mappings().fetchone()
        if user:
            user_email = user["email"]
        else:
            raise Exception("Invalid request")
        link_id = ""
        found = True
        # Prevent double link_id's
        while (found):
            link_id = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
            query = text("""
            SELECT sr.id FROM share_request sr WHERE sr.link_id = :link_id
            """)
            found = db.execute(query, {"link_id": link_id}).mappings().fetchone()

        date_from = datetime.strptime(valid_from, constants["DATE_FORMAT"]) if valid_from else None
        date_to = datetime.strptime(valid_to, constants["DATE_FORMAT"]) if valid_to else None

        # Insert share link record
        insert_query = text("""
        INSERT INTO share_request (user_email, phone_uuid, peripheral_ble_id, peripheral_name, reference, valid_from, valid_to, uses_limit, uses_left, link_id) VALUES (:user_email, :phone_uuid, :ble_id, :peripheral_name, :reference, :date_from, :date_to, :uses_limit, :uses_limit, :link_id)
        """)
        db.execute(insert_query, {"user_email": user_email, "phone_uuid": phone_uuid, "ble_id": ble_id, "peripheral_name": peripheral_name, "reference": reference, "date_from": date_from, "date_to": date_to, "uses_limit": uses_limit,
                                  "link_id": link_id})
        db.commit()

        return ResponseShareLink(link_id = link_id)

    except SQLAlchemyError as e:
        raise RuntimeError(f"Database error: {str(e)}")
    except Exception as e:
        raise Exception(f"Exception error: {str(e)}")

def set_share_uses(db: Session, link_id):
    update_query = text("""
    UPDATE share_request SET uses_left = uses_left - 1 WHERE link_id = :link_id
    """)
    try:
        db.execute(update_query,{"link_id": link_id})
        db.commit()

    except SQLAlchemyError as e:
        raise RuntimeError(f"Database error: {str(e)}")
    except Exception as e:
        raise Exception(f"Exception error: {str(e)}")

# Public peer code alphabet: 6 chars of [0-9 a-z A-Z] (62^6 ≈ 56 billion combos). Shown under a peer's
# profile picture; another peer types it to send a friend request. Generated with `secrets` for unbiased
# randomness, retried on the (vanishingly rare) collision.
_PEER_CODE_ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

def generate_peer_code(db: Session) -> str:
    for _ in range(25):
        code = "".join(secrets.choice(_PEER_CODE_ALPHABET) for _ in range(6))
        if not db.execute(text("SELECT 1 FROM user WHERE peer_name = :c"), {"c": code}).fetchone():
            return code
    raise Exception("Could not allocate a unique peer code")

def create_peer(db: Session, peer_uuid: bytes, name: str, about_me: str = ""):
    try:
        peer_code = generate_peer_code(db)
        insert_query = text("""
        INSERT INTO user (uuid, name, about_me, peer_name) VALUES (:uuid, :name, :about_me, :peer_name)
        """)
        # peer_uuid is the raw 16-byte value stored in the BINARY(16) `uuid` column.
        db.execute(insert_query, {"uuid": peer_uuid, "name": name, "about_me": about_me, "peer_name": peer_code})
        db.commit()

        # Convert the 16-byte value to a reversible ASCII (hex) string for the response.
        return ResponseCreatePeer(success=True, uuid=peer_uuid.hex(), peer_name=peer_code, error="")

    except SQLAlchemyError as e:
        raise RuntimeError(f"Database error: {str(e)}")
    except Exception as e:
        raise Exception(f"Exception error: {str(e)}")

def update_peer(db: Session, peer_hex: str, name: str = None, about_me: str = None):
    try:
        # The ASCII hex string from the API maps back to the raw 16-byte `uuid` column.
        try:
            peer_uuid = bytes.fromhex(peer_hex)
        except ValueError:
            raise Exception("Invalid peer uuid")
        if len(peer_uuid) != 16:
            raise Exception("Invalid peer uuid")

        # Only update the columns that were actually supplied; leave the rest untouched.
        fields = {}
        if name is not None:
            fields["name"] = name
        if about_me is not None:
            fields["about_me"] = about_me
        if not fields:
            raise Exception("No fields to update")

        set_clause = ", ".join(f"{column} = :{column}" for column in fields)
        update_query = text(f"""
        UPDATE user SET {set_clause} WHERE uuid = :uuid
        """)
        result = db.execute(update_query, {**fields, "uuid": peer_uuid})
        db.commit()
        if result.rowcount == 0:
            raise Exception("Peer not found")

        # Return the current values so the caller reflects the stored row.
        select_query = text("""
        SELECT name, about_me FROM user WHERE uuid = :uuid
        """)
        row = db.execute(select_query, {"uuid": peer_uuid}).mappings().fetchone()

        return ResponsePeer(
            success=True,
            uuid=peer_hex,
            name=row["name"] or "",
            about_me=row["about_me"] or "",
            error="",
        )

    except SQLAlchemyError as e:
        raise RuntimeError(f"Database error: {str(e)}")
    except Exception as e:
        raise Exception(f"Exception error: {str(e)}")

def _peer_uuid_bytes(peer_hex: str) -> bytes:
    """The ASCII hex string from the API → the raw 16-byte `uuid` column value."""
    try:
        peer_uuid = bytes.fromhex(peer_hex)
    except (ValueError, TypeError):
        raise Exception("Invalid peer uuid")
    if len(peer_uuid) != 16:
        raise Exception("Invalid peer uuid")
    return peer_uuid

def get_image_order(db: Session, peer_hex: str) -> list:
    """Read a peer's image_order — the comma-separated additional-image sequence numbers, in display order."""
    peer_uuid = _peer_uuid_bytes(peer_hex)
    row = db.execute(
        text("SELECT image_order FROM user WHERE uuid = :uuid"),
        {"uuid": peer_uuid},
    ).mappings().fetchone()
    if not row:
        raise Exception("Peer not found")
    raw = (row["image_order"] or "").strip()
    if not raw:
        return []
    return [int(part) for part in raw.split(",") if part.strip() != ""]

def set_image_order(db: Session, peer_hex: str, order: list) -> None:
    """Persist a peer's image_order list as a comma-separated string."""
    peer_uuid = _peer_uuid_bytes(peer_hex)
    value = ",".join(str(int(n)) for n in order)
    db.execute(
        text("UPDATE user SET image_order = :order WHERE uuid = :uuid"),
        {"order": value, "uuid": peer_uuid},
    )
    db.commit()

def get_peer(db: Session, peer_hex: str):
    try:
        # The ASCII hex string from the API maps back to the raw 16-byte `uuid` column.
        try:
            peer_uuid = bytes.fromhex(peer_hex)
        except ValueError:
            raise Exception("Invalid peer uuid")
        if len(peer_uuid) != 16:
            raise Exception("Invalid peer uuid")

        select_query = text("""
        SELECT name, about_me, peer_name FROM user WHERE uuid = :uuid
        """)
        row = db.execute(select_query, {"uuid": peer_uuid}).mappings().fetchone()
        if not row:
            raise Exception("Peer not found")

        # Lazy backfill: peers created before the peer_name column existed have none yet — mint one on
        # first lookup so every peer ends up with a code.
        peer_code = row["peer_name"]
        if not peer_code:
            peer_code = generate_peer_code(db)
            db.execute(text("UPDATE user SET peer_name = :c WHERE uuid = :uuid"),
                       {"c": peer_code, "uuid": peer_uuid})
            db.commit()

        return ResponsePeer(
            success=True,
            uuid=peer_hex,
            name=row["name"] or "",
            about_me=row["about_me"] or "",
            peer_name=peer_code,
            error="",
        )

    except SQLAlchemyError as e:
        raise RuntimeError(f"Database error: {str(e)}")
    except Exception as e:
        raise Exception(f"Exception error: {str(e)}")

def find_peer_by_code(db: Session, code: str):
    """Resolve a 6-char public peer code (peer_name) to {uuid (hex), name}, used when a peer types a code
    to send a friend request. Returns None when no peer has that code."""
    code = (code or "").strip()
    if not code:
        return None
    row = db.execute(
        text("SELECT uuid, name FROM user WHERE peer_name = :c"),
        {"c": code},
    ).mappings().fetchone()
    if not row:
        return None
    raw = row["uuid"]
    uuid_hex = raw.hex() if isinstance(raw, (bytes, bytearray)) else str(raw)
    return {"uuid": uuid_hex, "name": row["name"] or ""}

def peer_exists(db: Session, peer_hex: str) -> bool:
    """True if a row with this uuid exists in the user table — regardless of is_active, so an
    inactive peer (who set themselves invisible) can still reach activate_user and the other peer
    endpoints. Backs the check_peer_uuid auth gate and the /v1/check_peer/ launch check; a
    malformed/short hex simply returns False rather than raising."""
    try:
        peer_uuid = bytes.fromhex(peer_hex)
    except (ValueError, TypeError):
        return False
    if len(peer_uuid) != 16:
        return False
    try:
        row = db.execute(
            text("SELECT 1 FROM user WHERE uuid = :uuid LIMIT 1"),
            {"uuid": peer_uuid},
        ).fetchone()
        return row is not None
    except SQLAlchemyError:
        return False

def register_peer_token(db: Session, peer_hex: str, token: str):
    """Stores a peer's FCM push token (in the user table's fcm_token column), so the relay can
    wake/ring the peer with an INCOMING_CHAT push when its app is backgrounded. X-API-Key only —
    peers have no OAuth session, so this is keyed by uuid hex like create_peer / get_peer."""
    try:
        try:
            peer_uuid = bytes.fromhex(peer_hex)
        except ValueError:
            raise Exception("Invalid peer uuid")
        if len(peer_uuid) != 16:
            raise Exception("Invalid peer uuid")

        update_query = text("""
        UPDATE user SET fcm_token = :token WHERE uuid = :uuid
        """)
        result = db.execute(update_query, {"token": token, "uuid": peer_uuid})
        db.commit()
        if result.rowcount == 0:
            raise Exception("Peer not found")
        return ResponseResult(success=True, error="")

    except SQLAlchemyError as e:
        raise RuntimeError(f"Database error: {str(e)}")
    except Exception as e:
        raise Exception(f"Exception error: {str(e)}")

def register_peer_voip_token(db: Session, peer_hex: str, token: str):
    """Stores a peer's PushKit VoIP token (user.voip_token) so the relay can wake it with a native
    CallKit incoming-call screen for a call. Same X-API-Key / uuid-hex-keyed pattern as
    register_peer_token. Only CallKit-capable (non-China) peers register a VoIP token."""
    try:
        try:
            peer_uuid = bytes.fromhex(peer_hex)
        except ValueError:
            raise Exception("Invalid peer uuid")
        if len(peer_uuid) != 16:
            raise Exception("Invalid peer uuid")

        update_query = text("""
        UPDATE user SET voip_token = :token WHERE uuid = :uuid
        """)
        result = db.execute(update_query, {"token": token, "uuid": peer_uuid})
        db.commit()
        if result.rowcount == 0:
            raise Exception("Peer not found")
        return ResponseResult(success=True, error="")

    except SQLAlchemyError as e:
        raise RuntimeError(f"Database error: {str(e)}")
    except Exception as e:
        raise Exception(f"Exception error: {str(e)}")

def get_peer_push_info(db: Session, peer_hex: str):
    """Returns (fcm_token, name, voip_token) for a peer by hex uuid; (None, "", None) when
    unknown/invalid. voip_token is set only for CallKit-capable peers (used for call wake-ups)."""
    try:
        peer_uuid = bytes.fromhex(peer_hex)
    except ValueError:
        return (None, "", None)
    if len(peer_uuid) != 16:
        return (None, "", None)
    row = db.execute(
        text("SELECT fcm_token, name, voip_token FROM user WHERE uuid = :uuid"),
        {"uuid": peer_uuid},
    ).mappings().fetchone()
    if not row:
        return (None, "", None)
    return (row["fcm_token"], row["name"] or "", row["voip_token"])

def get_peer_name(db: Session, peer_hex: str):
    """Public name-only lookup for the invite landing page (no caller auth — a not-yet-installed
    visitor has no peer id). Returns the peer's name, or None if the uuid is unknown/invalid. Safe to
    expose: a peer uuid is a random 128-bit value, so names aren't enumerable, and only a name is returned."""
    try:
        peer_uuid = bytes.fromhex(peer_hex)
    except ValueError:
        return None
    if len(peer_uuid) != 16:
        return None
    row = db.execute(
        text("SELECT name FROM user WHERE uuid = :uuid"),
        {"uuid": peer_uuid},
    ).mappings().fetchone()
    return (row["name"] if row and row["name"] else None)

def _build_signal_payload(msg_type: str, sender_hex: str, sender_name: str, extra: dict = None, badge: int = None):
    """Builds the (data, AndroidConfig, APNSConfig) shared by the single- and multi-recipient signal
    pushes, so both fan-outs stay byte-for-byte identical. Mirrors the SafeXS doorbell push
    (notify_safexs_doorbell), proven to reach force-quit apps:
      • an aps.alert built via ApsAlert (no top-level `notification`),
      • sound="default" so even a force-quit app (where the in-app ringer can't run) makes an
        audible system sound on the lock screen,
      • content_available=True so a merely-suspended app is woken to ring, and
      • an explicit apns-push-type=alert header (priority 10) so APNs delivers+shows it rather than
        dropping it as a background push. No interruption-level → no 'TIME SENSITIVE' banner label.
    The iOS-facing action is INCOMING_CHAT for a chat request, INCOMING_CALL for a call request, and
    the same FRIEND_* string otherwise. `extra` adds string key/values to data (e.g. a call's video
    flag). Returns (data, android_config, apns_config)."""
    name = sender_name or "A peer"
    copy = {
        "CHAT_REQUEST":   ("Incoming chat",     f"{name} wants to chat"),
        "CALL_REQUEST":   ("Incoming call",     f"{name} is calling"),
        "CALL_CANCEL":    ("Missed call",       f"You missed a call from {name}"),
        "FRIEND_REQUEST": ("Friend Request",    f"{name} wants to be friends"),
        "FRIEND_ACCEPT":  ("New friend",        f"You're friends now with {name}"),
        "NOFRIEND":       ("Friend request",    f"{name} declined your friend request"),
        "UNFRIEND":       ("Friendship ended",  f"{name} ended the friendship"),
        "GROUP_INVITE":   ("Group invite",      f"{name} added you to a group"),
    }
    title, body = copy.get(msg_type, ("PEERS.CLUB", "New activity"))
    # A group invite names the group when it's carried in `extra` ("<name> added you to <group>").
    if msg_type == "GROUP_INVITE" and extra and extra.get("group_name"):
        body = f"{name} added you to {extra['group_name']}"
    # iOS routing actions: chat → INCOMING_CHAT, call → INCOMING_CALL, friend → the WS type verbatim.
    fcm_action = {"CHAT_REQUEST": "INCOMING_CHAT", "CALL_REQUEST": "INCOMING_CALL"}.get(msg_type, msg_type)
    data = {"action": fcm_action, "sender_id": sender_hex, "sender_name": name}
    if extra:
        data.update({k: str(v) for k, v in extra.items()})
    aps_object = messaging.Aps(
        alert=messaging.ApsAlert(title=title, body=body),
        sound="default",
        content_available=True,
        badge=badge,          # app-icon count for a killed/backgrounded app (None ⇒ unchanged)
        # Time Sensitive so a killed/backgrounded app's call/chat banner is prominent, retained on the
        # lock screen, and breaks through Focus/Do Not Disturb — matching the in-app local notification.
        custom_data={"interruption-level": "time-sensitive"},
    )
    # ttl=60 (not 0): "now or never" made FCM silently DROP the push whenever the phone was in a
    # Doze window even though send() returned True — a backgrounded receiver then never rang. 60s
    # comfortably covers the 45s ring window while still expiring stale signals.
    android_config = messaging.AndroidConfig(priority="high", ttl=60)
    apns_config = messaging.APNSConfig(
        headers={"apns-priority": "10", "apns-push-type": "alert"},
        payload=messaging.APNSPayload(aps=aps_object),
    )
    return data, android_config, apns_config


def send_silent_wake(target_token: str) -> bool:
    """Data-only 'NEARBY_WAKE': nudges a backgrounded/locked app to restart its BLE scan so a
    freshly-discoverable nearby peer is found in seconds instead of at the next address rotation
    (up to ~15 min for a locked iPhone's duplicate-filtered background scan). Silent on iOS
    (content-available, no alert — subject to Apple's silent-push budget), a plain data message on
    Android. False on not-configured / empty token / error."""
    if app_peers is None or not target_token:
        return False
    try:
        message = messaging.Message(
            token=target_token,
            data={"action": "NEARBY_WAKE"},
            android=messaging.AndroidConfig(priority="high", ttl=60),
            apns=messaging.APNSConfig(
                headers={"apns-priority": "5", "apns-push-type": "background"},
                payload=messaging.APNSPayload(aps=messaging.Aps(content_available=True)),
            ),
        )
        messaging.send(message, app=app_peers)
        return True
    except Exception as e:
        print(f"send_silent_wake error [{type(e).__name__}]: {e}")
        return False


def send_chat_message_push(target_token: str, sender_hex: str, sender_name: str, text: str, badge: int,
                           msg_id: str = "", video_id: str = "", kind_label: str = "") -> bool:
    """Visible 'new message' push for a FRIEND's chat message to an offline/backgrounded peer:
      • aps.alert (title = sender name, body = the message text) → a real banner on the lock screen
        / a notification while the receiver is in another app,
      • sound="default" so the receiver's system sound (or silence, per their settings/Focus) plays,
      • badge=<count> so the app icon shows the standard new-message count (set by the OS even while
        force-quit),
      • content_available=True so a merely-suspended app is woken to store the message in the
        background (so it's already in the transcript, not just the banner),
      • text + msg_id in `data` so the app stores the message and de-dups (a suspended app may process
        the push in the background AND again on tap). action=NEW_MESSAGE → tap opens the chat.
    False (no raise) on not-configured / empty-token / error."""
    if app_peers is None:
        print("send_chat_message_push: PEERS.CLUB Firebase app not configured — push skipped.")
        return False
    if not target_token:
        return False
    name = sender_name or "A peer"
    body = text or kind_label or "New message"
    data = {"action": "NEW_MESSAGE", "sender_id": sender_hex, "sender_name": name,
            "text": text or "", "msg_id": msg_id or "", "video_id": video_id or ""}
    aps_object = messaging.Aps(
        alert=messaging.ApsAlert(title=name, body=body),
        sound="default",
        badge=badge,
        content_available=True,
    )
    android_config = messaging.AndroidConfig(priority="high", ttl=3600)   # survive short Doze/offline windows (was ttl=0)
    apns_config = messaging.APNSConfig(
        headers={"apns-priority": "10", "apns-push-type": "alert"},
        payload=messaging.APNSPayload(aps=aps_object),
    )
    try:
        message = messaging.Message(token=target_token, data=data, android=android_config, apns=apns_config)
        response = messaging.send(message, app=app_peers)
        print(f"send_chat_message_push: from {sender_hex[:8]} badge={badge} → {response}")
        return True
    except Exception as e:
        print(f"send_chat_message_push error [{type(e).__name__}]: {e}")
        return False


def send_group_message_push(target_token: str, sender_hex: str, sender_name: str, group_id: str,
                            group_name: str, text: str, badge: int, msg_id: str = "") -> bool:
    """Visible 'new group message' push to ONE offline/backgrounded group member. Title = the group name,
    body = '<sender>: <text>'. action=GROUP_MESSAGE + group_id/group_name so a tap opens the group chat,
    text + msg_id so the app stores the message (de-dup). False (no raise) on not-configured/empty/error."""
    if app_peers is None:
        print("send_group_message_push: PEERS.CLUB Firebase app not configured — push skipped.")
        return False
    if not target_token:
        return False
    name = sender_name or "A peer"
    title = group_name or "Group"
    body = f"{name}: {text}" if text else f"{name} sent a message"
    data = {"action": "GROUP_MESSAGE", "sender_id": sender_hex, "sender_name": name,
            "group_id": str(group_id), "group_name": group_name or "", "text": text or "", "msg_id": msg_id or ""}
    aps_object = messaging.Aps(
        alert=messaging.ApsAlert(title=title, body=body),
        sound="default",
        badge=badge,
        content_available=True,
        custom_data={"interruption-level": "time-sensitive"},
    )
    android_config = messaging.AndroidConfig(priority="high", ttl=3600)   # survive short Doze/offline windows (was ttl=0)
    apns_config = messaging.APNSConfig(
        headers={"apns-priority": "10", "apns-push-type": "alert"},
        payload=messaging.APNSPayload(aps=aps_object),
    )
    try:
        message = messaging.Message(token=target_token, data=data, android=android_config, apns=apns_config)
        response = messaging.send(message, app=app_peers)
        print(f"send_group_message_push: group {group_id} from {sender_hex[:8]} badge={badge} → {response}")
        return True
    except Exception as e:
        print(f"send_group_message_push error [{type(e).__name__}]: {e}")
        return False


def send_group_call_push(target_token: str, sender_hex: str, sender_name: str, group_id: str,
                         group_name: str, video: bool) -> bool:
    """Visible 'incoming group call' push to ONE offline/backgrounded member (FCM alert; no CallKit for
    groups yet). Title = the group name, body = '<name> is starting a group audio/video call'. action =
    GROUP_CALL_REQUEST + group_id/group_name/video so the app rings the incoming group-call dialog on tap.
    False (no raise) on not-configured / empty token / error."""
    if app_peers is None:
        print("send_group_call_push: PEERS.CLUB Firebase app not configured — push skipped.")
        return False
    if not target_token:
        return False
    name = sender_name or "A peer"
    title = group_name or "Group call"
    body = f"{name} is starting a group {'video' if video else 'audio'} call"
    data = {"action": "GROUP_CALL_REQUEST", "sender_id": sender_hex, "sender_name": name,
            "group_id": str(group_id), "group_name": group_name or "", "video": "1" if video else "0"}
    aps_object = messaging.Aps(
        alert=messaging.ApsAlert(title=title, body=body),
        sound="default",
        content_available=True,
        custom_data={"interruption-level": "time-sensitive"},
    )
    android_config = messaging.AndroidConfig(priority="high", ttl=60)   # covers the ring window; was ttl=0 (dropped in Doze)
    apns_config = messaging.APNSConfig(
        headers={"apns-priority": "10", "apns-push-type": "alert"},
        payload=messaging.APNSPayload(aps=aps_object),
    )
    try:
        message = messaging.Message(token=target_token, data=data, android=android_config, apns=apns_config)
        response = messaging.send(message, app=app_peers)
        print(f"send_group_call_push: group {group_id} from {sender_hex[:8]} → {response}")
        return True
    except Exception as e:
        print(f"send_group_call_push error [{type(e).__name__}]: {e}")
        return False


def send_signal_push(target_token: str, msg_type: str, sender_hex: str, sender_name: str, extra: dict = None, badge: int = None) -> bool:
    """Pushes a signaling event (chat / friend / call) to ONE backgrounded/killed peer via the
    PEERS.CLUB Firebase app. Payload is built by _build_signal_payload (mirrors the SafeXS doorbell
    push). For fanning the same signal out to several devices (group calls) use send_signal_push_multi.
    False (no raise) on not-configured / empty-token / error.

    NOTE: delivery to iOS requires the peers-club Firebase project to have an APNs Authentication Key
    configured (Project Settings → Cloud Messaging). Without it FCM returns THIRD_PARTY_AUTH_ERROR."""
    if app_peers is None:
        print("send_signal_push: PEERS.CLUB Firebase app not configured — push skipped.")
        return False
    if not target_token:
        return False
    data, android_config, apns_config = _build_signal_payload(msg_type, sender_hex, sender_name, extra, badge)
    try:
        message = messaging.Message(
            token=target_token,
            data=data,
            android=android_config,
            apns=apns_config,
        )
        response = messaging.send(message, app=app_peers)
        print(f"send_signal_push: {msg_type} from {sender_hex[:8]} → {response}")
        return True
    except Exception as e:
        print(f"send_signal_push error [{type(e).__name__}]: {e}")
        return False


# ---------------------------------------------------------------------------------------------
# Direct APNs PushKit VoIP sender. FCM CANNOT deliver VoIP pushes (they need a separate PushKit
# token), so this talks to APNs HTTP/2 directly to wake a killed/locked peer so CallKit shows the
# native incoming-call screen. Auth is a provider JWT (ES256) signed with the APNs Auth Key (.p8) —
# this .p8 lives ON THE BACKEND and is SEPARATE from the one uploaded to Firebase for FCM.
#
# The KEY_ID and TEAM_ID below are NOT secrets (the Key ID is sent to Apple in every JWT) — they're
# set here for an env-var-free install; an env var still overrides on another server. Only the .p8
# FILE is secret (keep it out of git, like serviceAccountKeyPeersClub.json). Values are your Apple
# team (3V394W95NG) and its APNs key (6XMZLTFG8H). VERIFY the Key ID matches the .p8 you deploy: if
# your peers-club .p8 is a DIFFERENT key than the SafeXS-team one, put ITS Key ID here.
# ---------------------------------------------------------------------------------------------
# Resolve the .p8 relative to the backend root (where main.py lives), NOT the process CWD. A bare
# relative "AuthKeyPeersClub.p8" silently breaks (FileNotFoundError → VoIP push fails → calls fall back to
# FCM and become unstable) whenever uvicorn is launched from a different working directory after a redeploy.
_BACKEND_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APNS_AUTH_KEY_PATH = os.environ.get("APNS_AUTH_KEY_PATH", os.path.join(_BACKEND_ROOT, "AuthKeyPeersClub.p8"))
APNS_KEY_ID = os.environ.get("APNS_KEY_ID", "M2RKXMS874") #6XMZLTFG8H
APNS_TEAM_ID = os.environ.get("APNS_TEAM_ID", "3V394W95NG")
APNS_VOIP_TOPIC = os.environ.get("APNS_VOIP_TOPIC", "club.peers.ios.voip")
_APNS_HOST_PROD = "api.push.apple.com"
_APNS_HOST_SANDBOX = "api.sandbox.push.apple.com"

_apns_jwt = {"token": None, "iat": 0}
_apns_client = None

def _apns_auth_token():
    """Cached APNs provider JWT (ES256), refreshed every 40 min (Apple accepts 20–60 min)."""
    now = int(time.time())
    if _apns_jwt["token"] and now - _apns_jwt["iat"] < 2400:
        return _apns_jwt["token"]
    with open(APNS_AUTH_KEY_PATH, "r") as f:
        key = f.read()
    token = jwt.encode({"iss": APNS_TEAM_ID, "iat": now}, key, algorithm="ES256", headers={"kid": APNS_KEY_ID})
    _apns_jwt["token"] = token
    _apns_jwt["iat"] = now
    return token

def _apns_post(host: str, voip_token: str, payload: dict, auth: str):
    global _apns_client
    if _apns_client is None:
        _apns_client = httpx.Client(http2=True, timeout=10.0)   # keeps the HTTP/2 connection alive
    headers = {
        "authorization": f"bearer {auth}",
        "apns-topic": APNS_VOIP_TOPIC,
        "apns-push-type": "voip",
        "apns-priority": "10",
        "apns-expiration": "0",
    }
    return _apns_client.post(f"https://{host}/3/device/{voip_token}", json=payload, headers=headers)

def send_voip_push(voip_token: str, msg_type: str, sender_hex: str, sender_name: str, extra: dict = None) -> bool:
    """Sends a PushKit VoIP push DIRECTLY to APNs so a killed/locked peer rings via CallKit. The
    payload's top-level keys (action/sender_id/sender_name/video) match what the iOS PushKit handler
    reads. Tries production APNs, retrying sandbox on BadDeviceToken (dev builds use sandbox tokens).
    False (no raise) on not-configured / empty-token / error — caller can then fall back to FCM."""
    if not voip_token:
        return False
    if not (APNS_KEY_ID and APNS_TEAM_ID):
        print("send_voip_push: APNS_KEY_ID/APNS_TEAM_ID not configured — VoIP push skipped.")
        return False
    payload = {"aps": {}, "action": msg_type, "sender_id": sender_hex, "sender_name": sender_name or ""}
    if extra:
        payload.update(extra)
    try:
        auth = _apns_auth_token()
        resp = _apns_post(_APNS_HOST_PROD, voip_token, payload, auth)
        if resp.status_code == 400 and "BadDeviceToken" in resp.text:
            resp = _apns_post(_APNS_HOST_SANDBOX, voip_token, payload, auth)
        if resp.status_code == 200:
            print(f"send_voip_push: {msg_type} from {sender_hex[:8]} → 200")
            return True
        print(f"send_voip_push error: {resp.status_code} {resp.text}")
        return False
    except Exception as e:
        print(f"send_voip_push error [{type(e).__name__}]: {e}")
        return False


def send_signal_push_multi(target_tokens, msg_type: str, sender_hex: str, sender_name: str, extra: dict = None) -> int:
    """Multicast variant of send_signal_push: fans the SAME signal out to several devices at once —
    groundwork for group calls (ring every group member's phone with one call). Reuses the exact
    SafeXS-mirroring payload via _build_signal_payload, so single- and multi-recipient pushes are
    identical. Empty/None and duplicate tokens are dropped; the rest are sent in batches of 500 (the
    FCM multicast limit) via send_each_for_multicast. Returns the number of devices APNs/FCM accepted
    the push for (0 on not-configured / no-tokens; partial counts survive per-token failures)."""
    if app_peers is None:
        print("send_signal_push_multi: PEERS.CLUB Firebase app not configured — push skipped.")
        return 0
    # De-dupe while preserving order, dropping falsy tokens (same peer on two devices → one entry).
    tokens = list(dict.fromkeys(t for t in (target_tokens or []) if t))
    if not tokens:
        return 0
    data, android_config, apns_config = _build_signal_payload(msg_type, sender_hex, sender_name, extra)
    sent = 0
    try:
        for i in range(0, len(tokens), 500):
            batch = tokens[i:i + 500]
            multicast = messaging.MulticastMessage(
                tokens=batch,
                data=data,
                android=android_config,
                apns=apns_config,
            )
            resp = messaging.send_each_for_multicast(multicast, app=app_peers)
            sent += resp.success_count
            if resp.failure_count:
                for idx, r in enumerate(resp.responses):
                    if not r.success:
                        print(f"send_signal_push_multi: token {batch[idx][:12]}… failed: {r.exception}")
        print(f"send_signal_push_multi: {msg_type} from {sender_hex[:8]} → {sent}/{len(tokens)} delivered")
        return sent
    except Exception as e:
        print(f"send_signal_push_multi error [{type(e).__name__}]: {e}")
        return sent

def send_chat_push(target_token: str, sender_hex: str, sender_name: str) -> bool:
    """Backward-compatible wrapper — a chat request push."""
    return send_signal_push(target_token, "CHAT_REQUEST", sender_hex, sender_name)

def add_friend(db: Session, user_hex: str, friend_hex: str):
    """Inserts a friend link (user_hex -> friend_hex) into user_user. X-API-Key only; idempotent
    (adding an existing friend succeeds without a duplicate row).

    NOTE: column names assumed to be (user_id, friend_id) holding the BINARY(16) uuids, matching
    the user_peripheral.user_id convention. Adjust the two SQL statements if user_user differs."""
    try:
        try:
            user_uuid = bytes.fromhex(user_hex)
            friend_uuid = bytes.fromhex(friend_hex)
        except ValueError:
            raise Exception("Invalid uuid")
        if len(user_uuid) != 16 or len(friend_uuid) != 16:
            raise Exception("Invalid uuid")
        if user_uuid == friend_uuid:
            raise Exception("Cannot add yourself as a friend")

        existing = db.execute(
            text("SELECT 1 FROM user_user WHERE uuid_1 = :u AND uuid_2 = :f"),
            {"u": user_uuid, "f": friend_uuid},
        ).fetchone()
        if not existing:
            db.execute(
                text("INSERT INTO user_user (uuid_1, uuid_2) VALUES (:u, :f)"),
                {"u": user_uuid, "f": friend_uuid},
            )
            db.commit()
        return ResponseResult(success=True, error="")

    except SQLAlchemyError as e:
        raise RuntimeError(f"Database error: {str(e)}")
    except Exception as e:
        raise Exception(f"Exception error: {str(e)}")

def cancel_friend(db: Session, user_hex: str, friend_hex: str):
    """Ends a friendship: removes the user_user link in BOTH directions (the row may have been
    created by either side via add_friend). X-API-Key only; idempotent.

    NOTE: same (user_id, friend_id) column assumption as add_friend — confirm against user_user."""
    try:
        try:
            user_uuid = bytes.fromhex(user_hex)
            friend_uuid = bytes.fromhex(friend_hex)
        except ValueError:
            raise Exception("Invalid uuid")
        if len(user_uuid) != 16 or len(friend_uuid) != 16:
            raise Exception("Invalid uuid")

        db.execute(
            text("""
            DELETE FROM user_user
        WHERE (uuid_1 = :u AND uuid_2 = :f) OR (uuid_1 = :f AND uuid_2 = :u)
            """),
            {"u": user_uuid, "f": friend_uuid},
        )
        db.commit()
        return ResponseResult(success=True, error="")

    except SQLAlchemyError as e:
        raise RuntimeError(f"Database error: {str(e)}")
    except Exception as e:
        raise Exception(f"Exception error: {str(e)}")

def are_friends(db: Session, hex_a: str, hex_b: str) -> bool:
    """True if an ACTIVE user_user link exists between the two peers (either direction). Used to gate
    the killed/offline FCM wake to friends only. is_active = 0 means the combination is BLOCKED, so a
    blocked pair are NOT friends (and a block can't wake the other)."""
    try:
        a = bytes.fromhex(hex_a)
        b = bytes.fromhex(hex_b)
    except (ValueError, TypeError):
        return False
    if len(a) != 16 or len(b) != 16:
        return False
    try:
        row = db.execute(
            text("""SELECT 1 FROM user_user
                    WHERE ((uuid_1 = :a AND uuid_2 = :b) OR (uuid_1 = :b AND uuid_2 = :a))
                      AND is_active = 1 LIMIT 1"""),
            {"a": a, "b": b},
        ).fetchone()
        return row is not None
    except SQLAlchemyError:
        return False

def block_peer(db: Session, user_hex: str, blocked_hex: str):
    """Permanently blocks the combination of two peers by marking their user_user link is_active = 0
    (creating the link if none exists). A blocked combination is excluded everywhere — are_friends,
    get_friends and peers_online all require is_active = 1. Idempotent; either direction is matched."""
    try:
        try:
            u = bytes.fromhex(user_hex)
            b = bytes.fromhex(blocked_hex)
        except ValueError:
            raise Exception("Invalid uuid")
        if len(u) != 16 or len(b) != 16:
            raise Exception("Invalid uuid")
        if u == b:
            raise Exception("Cannot block yourself")
        result = db.execute(
            text("""UPDATE user_user SET is_active = 0
                    WHERE (uuid_1 = :u AND uuid_2 = :b) OR (uuid_1 = :b AND uuid_2 = :u)"""),
            {"u": u, "b": b},
        )
        if result.rowcount == 0:
            db.execute(
                text("INSERT INTO user_user (uuid_1, uuid_2, is_active) VALUES (:u, :b, 0)"),
                {"u": u, "b": b},
            )
        db.commit()
        return ResponseResult(success=True, error="")
    except SQLAlchemyError as e:
        raise RuntimeError(f"Database error: {str(e)}")
    except Exception as e:
        raise Exception(f"Exception error: {str(e)}")

def is_blocked(db: Session, hex_a: str, hex_b: str) -> bool:
    """True if peers a and b are blocked — a user_user link with is_active = 0 in EITHER direction. Used
    by the relay to refuse to deliver chat messages / call signals between a blocked combination."""
    try:
        a = bytes.fromhex(hex_a)
        b = bytes.fromhex(hex_b)
    except (ValueError, TypeError):
        return False
    if len(a) != 16 or len(b) != 16:
        return False
    row = db.execute(
        text("""SELECT 1 FROM user_user
                WHERE ((uuid_1 = :a AND uuid_2 = :b) OR (uuid_1 = :b AND uuid_2 = :a))
                  AND is_active = 0 LIMIT 1"""),
        {"a": a, "b": b},
    ).fetchone()
    return row is not None

def blocked_peer_set(db: Session, user_hex: str, peer_hexes):
    """Returns the subset of peer_hexes that are BLOCKED with user_hex (a user_user link with
    is_active = 0 in either direction), so peers_online can drop them from the nearby list."""
    try:
        me = bytes.fromhex(user_hex)
    except (ValueError, TypeError):
        return set()
    if len(me) != 16:
        return set()
    blocked = set()
    for peer_hex in peer_hexes:
        try:
            p = bytes.fromhex(peer_hex)
        except (ValueError, TypeError):
            continue
        if len(p) != 16:
            continue
        row = db.execute(
            text("""SELECT 1 FROM user_user
                    WHERE ((uuid_1 = :me AND uuid_2 = :p) OR (uuid_1 = :p AND uuid_2 = :me))
                      AND is_active = 0 LIMIT 1"""),
            {"me": me, "p": p},
        ).fetchone()
        if row:
            blocked.add(peer_hex)
    return blocked

def delete_peer(db: Session, peer_hex: str):
    """Permanently deletes a peer: removes any user_user friend links (both directions) and then
    the user row itself. The profile image file is removed by the endpoint (which owns PROFILE_DIR).
    X-API-Key only; idempotent — deleting an already-gone peer still returns success."""
    try:
        try:
            peer_uuid = bytes.fromhex(peer_hex)
        except (ValueError, TypeError):
            raise Exception("Invalid peer uuid")
        if len(peer_uuid) != 16:
            raise Exception("Invalid peer uuid")

        # Remove everything referencing the user before the user row itself (the Groups tables
        # arrived after this function was first written — leaving them made the delete fail /
        # orphan rows). Order: memberships of groups THEY admin, their admin'd groups, their own
        # memberships, friend links (either direction), then the user row.
        db.execute(
            text("DELETE ug FROM user_group ug JOIN `group` g ON g.id = ug.group_id WHERE g.admin_user_uuid = :uuid"),
            {"uuid": peer_uuid},
        )
        db.execute(
            text("DELETE FROM `group` WHERE admin_user_uuid = :uuid"),
            {"uuid": peer_uuid},
        )
        db.execute(
            text("DELETE FROM user_group WHERE user_uuid = :uuid"),
            {"uuid": peer_uuid},
        )
        db.execute(
            text("DELETE FROM user_user WHERE uuid_1 = :uuid OR uuid_2 = :uuid"),
            {"uuid": peer_uuid},
        )
        db.execute(
            text("DELETE FROM user WHERE uuid = :uuid"),
            {"uuid": peer_uuid},
        )
        db.commit()
        return ResponseResult(success=True, error="")

    except SQLAlchemyError as e:
        raise RuntimeError(f"Database error: {str(e)}")
    except Exception as e:
        raise Exception(f"Exception error: {str(e)}")

def get_friends(db: Session, user_hex: str):
    """Returns the user's friends — both directions of the user_user link (whoever called
    add_friend created a single A→B row) — as dicts {uuid (hex), name, about_me}. Images are
    attached by the endpoint. UNION de-duplicates if a reciprocal link ever exists."""
    try:
        user_uuid = bytes.fromhex(user_hex)
    except (ValueError, TypeError):
        raise Exception("Invalid uuid")
    if len(user_uuid) != 16:
        raise Exception("Invalid uuid")

    rows = db.execute(
        text("""
        SELECT u.uuid AS fuid, u.name AS name, u.about_me AS about_me
        FROM user_user uu JOIN user u ON u.uuid = uu.uuid_2
        WHERE uu.uuid_1 = :me AND uu.is_active = 1
        UNION
        SELECT u.uuid AS fuid, u.name AS name, u.about_me AS about_me
        FROM user_user uu JOIN user u ON u.uuid = uu.uuid_1
        WHERE uu.uuid_2 = :me AND uu.is_active = 1
        """),
        {"me": user_uuid},
    ).mappings().fetchall()

    return [
        {"uuid": r["fuid"].hex(), "name": r["name"] or "", "about_me": r["about_me"] or ""}
        for r in rows
    ]

# --- Groups ------------------------------------------------------------------------------------------
# A `group` row is (id AUTO_INCREMENT, group_name, admin_user_uuid BINARY(16)). Membership lives in
# `user_group` (uuid BINARY(16), group_id INT) — the admin is inserted as a member at creation, so the
# group surfaces in his list immediately and joiners are appended as they accept the invite. `group` is a
# reserved word in MySQL, so it is back-ticked everywhere.

def create_group(db: Session, admin_hex: str, group_name: str) -> int:
    """Creates a group owned by admin_hex and adds the admin as the first member. Returns the new
    group id (the AUTO_INCREMENT primary key — used for the image filename group_<id>.png)."""
    admin_uuid = _peer_uuid_bytes(admin_hex)
    name = (group_name or "").strip() or "Group"
    result = db.execute(
        text("INSERT INTO `group` (name, admin_user_uuid) VALUES (:n, :a)"),
        {"n": name, "a": admin_uuid},
    )
    group_id = int(result.lastrowid)
    db.execute(
        text("INSERT INTO user_group (user_uuid, group_id) VALUES (:u, :g)"),
        {"u": admin_uuid, "g": group_id},
    )
    db.commit()
    return group_id

def group_exists(db: Session, group_id: int) -> bool:
    """True if a group row with this id still exists (used to reject joining a deleted group)."""
    row = db.execute(text("SELECT 1 FROM `group` WHERE id = :g"), {"g": group_id}).fetchone()
    return row is not None

def remove_group_member(db: Session, member_hex: str, group_id: int):
    """Removes member_hex from a group (admin-only — the endpoint authorises). Idempotent."""
    member_uuid = _peer_uuid_bytes(member_hex)
    db.execute(
        text("DELETE FROM user_group WHERE user_uuid = :u AND group_id = :g"),
        {"u": member_uuid, "g": group_id},
    )
    db.commit()
    return ResponseResult(success=True, error="")

def add_group_member(db: Session, user_hex: str, group_id: int):
    """Adds user_hex to a group (idempotent). Called when a friend taps Join on the invite card."""
    user_uuid = _peer_uuid_bytes(user_hex)
    existing = db.execute(
        text("SELECT 1 FROM user_group WHERE user_uuid = :u AND group_id = :g"),
        {"u": user_uuid, "g": group_id},
    ).fetchone()
    if not existing:
        db.execute(
            text("INSERT INTO user_group (user_uuid, group_id) VALUES (:u, :g)"),
            {"u": user_uuid, "g": group_id},
        )
        db.commit()
    return ResponseResult(success=True, error="")

def get_groups(db: Session, user_hex: str):
    """Returns the groups the user belongs to as dicts {id, group_name, admin_uuid (hex)}. Images are
    attached by the endpoint (group_<id>.png in PROFILE_DIR)."""
    user_uuid = _peer_uuid_bytes(user_hex)
    rows = db.execute(
        text("""
        SELECT g.id AS id, g.name AS group_name, g.about_us AS about_us, g.admin_user_uuid AS admin
        FROM user_group ug JOIN `group` g ON g.id = ug.group_id
        WHERE ug.user_uuid = :me
        """),
        {"me": user_uuid},
    ).mappings().fetchall()
    return [
        {"id": int(r["id"]), "group_name": r["group_name"] or "", "about_us": r["about_us"] or "",
         "admin_uuid": r["admin"].hex() if r["admin"] else ""}
        for r in rows
    ]

def group_members(db: Session, group_id: int):
    """Returns a group's members as dicts {uuid (hex), name}. Profile images are attached by the
    endpoint (peer_<uuid>.jpg), like get_friends."""
    rows = db.execute(
        text("""
        SELECT u.uuid AS uuid, u.name AS name
        FROM user_group ug JOIN user u ON u.uuid = ug.user_uuid
        WHERE ug.group_id = :g
        """),
        {"g": group_id},
    ).mappings().fetchall()
    return [{"uuid": r["uuid"].hex(), "name": r["name"] or ""} for r in rows]

def group_admin_hex(db: Session, group_id: int):
    """The hex uuid of a group's admin, or None if the group doesn't exist."""
    row = db.execute(
        text("SELECT admin_user_uuid FROM `group` WHERE id = :g"),
        {"g": group_id},
    ).mappings().fetchone()
    return row["admin_user_uuid"].hex() if row and row["admin_user_uuid"] else None

def group_name(db: Session, group_id: int) -> str:
    """The group's name (empty string if unknown)."""
    row = db.execute(text("SELECT name FROM `group` WHERE id = :g"), {"g": group_id}).mappings().fetchone()
    return (row["name"] if row and row["name"] else "")

def group_member_hexes(db: Session, group_id: int):
    """Hex uuids of every member of a group (so the relay / endpoints can reach them)."""
    rows = db.execute(
        text("SELECT user_uuid FROM user_group WHERE group_id = :g"),
        {"g": group_id},
    ).fetchall()
    return [r[0].hex() for r in rows]

def update_group_name(db: Session, group_id: int, name: str):
    """Renames a group (admin-only — the endpoint authorises). Idempotent."""
    db.execute(
        text("UPDATE `group` SET name = :n WHERE id = :g"),
        {"n": (name or "").strip() or "Group", "g": group_id},
    )
    db.commit()
    return ResponseResult(success=True, error="")

def update_group_about_us(db: Session, group_id: int, about_us: str):
    """Sets a group's about_us text (admin-only — the endpoint authorises). Idempotent."""
    db.execute(
        text("UPDATE `group` SET about_us = :a WHERE id = :g"),
        {"a": about_us or "", "g": group_id},
    )
    db.commit()
    return ResponseResult(success=True, error="")

def delete_group(db: Session, group_id: int):
    """Deletes a group and all its memberships (admin-only — the endpoint authorises). The image file
    is removed by the endpoint (which owns PROFILE_DIR). Idempotent."""
    db.execute(text("DELETE FROM user_group WHERE group_id = :g"), {"g": group_id})
    db.execute(text("DELETE FROM `group` WHERE id = :g"), {"g": group_id})
    db.commit()
    return ResponseResult(success=True, error="")

def filter_active_peers(db: Session, peer_hexes):
    """Given a list of hex uuids, returns those whose user row has is_active = 1 (i.e. the peer
    hasn't set themselves inactive). Inactive peers are dropped so they disappear from other phones'
    nearby lists. The input list is small (a caller's BLE-nearby group), so a per-id lookup is fine."""
    active = []
    for peer_hex in peer_hexes:
        try:
            peer_uuid = bytes.fromhex(peer_hex)
        except (ValueError, TypeError):
            continue
        if len(peer_uuid) != 16:
            continue
        row = db.execute(
            text("SELECT is_active FROM user WHERE uuid = :uuid"),
            {"uuid": peer_uuid},
        ).mappings().fetchone()
        if row and row["is_active"]:
            active.append(peer_hex)
    return active

def active_status(db: Session, peer_hexes):
    """ONE round-trip: returns {hex_uuid: bool(is_active)} for the queried peers that exist. Lets
    peers_online derive BOTH `online` (connected AND active) and `inactive` (is_active=0) from a single
    query instead of a per-id SELECT each — so a presence poll touches the DB once, not 2×N times. Uses
    explicit named placeholders (the BLE-nearby group is small) for portability across SQLAlchemy/drivers."""
    by_uuid = {}
    for peer_hex in peer_hexes:
        try:
            b = bytes.fromhex(peer_hex)
        except (ValueError, TypeError):
            continue
        if len(b) == 16:
            by_uuid[b] = peer_hex
    if not by_uuid:
        return {}
    keys = list(by_uuid.keys())
    placeholders = ", ".join(f":u{i}" for i in range(len(keys)))
    bind = {f"u{i}": k for i, k in enumerate(keys)}
    rows = db.execute(
        text(f"SELECT uuid, is_active FROM user WHERE uuid IN ({placeholders})"),
        bind,
    ).mappings().all()
    status = {}
    for row in rows:
        key = bytes(row["uuid"])            # normalise (driver may hand back bytearray/memoryview)
        if key in by_uuid:
            status[by_uuid[key]] = bool(row["is_active"])
    return status

def closed_peer_set(db: Session, peer_hexes):
    """Returns the subset of peer_hexes that are NOT open to making new friends (user.is_open_for_new = 0),
    so peers_online can tell the app to hide them from Nearby (the app keeps ones that are already friends).
    ONE round-trip, mirroring active_status. Peers whose row is missing the column/value are treated as OPEN
    (not returned) so nothing is hidden by accident."""
    by_uuid = {}
    for peer_hex in peer_hexes:
        try:
            b = bytes.fromhex(peer_hex)
        except (ValueError, TypeError):
            continue
        if len(b) == 16:
            by_uuid[b] = peer_hex
    if not by_uuid:
        return set()
    keys = list(by_uuid.keys())
    placeholders = ", ".join(f":u{i}" for i in range(len(keys)))
    bind = {f"u{i}": k for i, k in enumerate(keys)}
    rows = db.execute(
        text(f"SELECT uuid, is_open_for_new FROM user WHERE uuid IN ({placeholders})"),
        bind,
    ).mappings().all()
    closed = set()
    for row in rows:
        key = bytes(row["uuid"])
        val = row["is_open_for_new"]
        # Only an EXPLICIT 0 hides a peer. NULL / missing → treated as OPEN, so a pre-existing user whose
        # column was never set can't accidentally disappear from everyone's Nearby list.
        if key in by_uuid and val is not None and not bool(val):
            closed.add(by_uuid[key])
    return closed

def hide_live_set(db: Session, peer_hexes):
    """Returns the subset of peer_hexes that HIDE their live status (user.hide_live = 1): peers_online
    drops them from `connected`, so friends never see the blue "app open" LED for them. ONE round-trip,
    mirroring closed_peer_set. Missing column raises (caller treats as nobody hidden); NULL/0 → visible,
    so pre-existing users can't accidentally hide."""
    by_uuid = {}
    for peer_hex in peer_hexes:
        try:
            b = bytes.fromhex(peer_hex)
        except (ValueError, TypeError):
            continue
        if len(b) == 16:
            by_uuid[b] = peer_hex
    if not by_uuid:
        return set()
    keys = list(by_uuid.keys())
    placeholders = ", ".join(f":u{i}" for i in range(len(keys)))
    bind = {f"u{i}": k for i, k in enumerate(keys)}
    rows = db.execute(
        text(f"SELECT uuid, hide_live FROM user WHERE uuid IN ({placeholders})"),
        bind,
    ).mappings().all()
    hidden = set()
    for row in rows:
        key = bytes(row["uuid"])
        val = row["hide_live"]
        if key in by_uuid and val is not None and bool(val):
            hidden.add(by_uuid[key])
    return hidden

def update_hide_live(db: Session, user_hex: str, hide: bool):
    """Sets a peer's hide_live flag ("Hide my live status" in Settings). X-API-Key only."""
    try:
        try:
            user_uuid = bytes.fromhex(user_hex)
        except ValueError:
            raise Exception("Invalid uuid")
        if len(user_uuid) != 16:
            raise Exception("Invalid uuid")

        result = db.execute(
            text("UPDATE user SET hide_live = :hide WHERE uuid = :uuid"),
            {"hide": 1 if hide else 0, "uuid": user_uuid},
        )
        db.commit()
        if result.rowcount == 0:
            raise Exception("Peer not found")
        return ResponseResult(success=True, error="")

    except SQLAlchemyError as e:
        raise RuntimeError(f"Database error: {str(e)}")
    except Exception as e:
        raise Exception(f"Exception error: {str(e)}")

def update_open_to_friends(db: Session, user_hex: str, is_open: bool):
    """Sets a peer's is_open_for_new flag (open to making new friends = discoverable by nearby non-friends).
    X-API-Key only. Mirrors activate_user; does NOT filter on any flag so it always applies."""
    try:
        try:
            user_uuid = bytes.fromhex(user_hex)
        except ValueError:
            raise Exception("Invalid uuid")
        if len(user_uuid) != 16:
            raise Exception("Invalid uuid")

        result = db.execute(
            text("UPDATE user SET is_open_for_new = :open WHERE uuid = :uuid"),
            {"open": 1 if is_open else 0, "uuid": user_uuid},
        )
        db.commit()
        if result.rowcount == 0:
            raise Exception("Peer not found")
        return ResponseResult(success=True, error="")

    except SQLAlchemyError as e:
        raise RuntimeError(f"Database error: {str(e)}")
    except Exception as e:
        raise Exception(f"Exception error: {str(e)}")

def activate_user(db: Session, user_hex: str, is_active: bool):
    """Sets a peer's is_active flag (Peers-mode active = discoverable). X-API-Key only. Deliberately
    does NOT filter on is_active in the WHERE clause so an already-inactive user can re-activate.

    NOTE: for PEERS, is_active now means ONLY 'discoverable nearby' — since inactive (Friends mode /
    low-power sleep) is the default, the peer-by-uuid queries (get_peer / update_peer / image_order /
    register_peer_token / register_peer_voip_token / get_peer_push_info / get_peer_name) must NOT filter
    on it, or sleeping peers couldn't be profiled, messaged, or PUSHED a call/chat. Only peers_online
    (active_status / filter_active_peers) reads is_active, as the discovery gate. The email-keyed admin
    login queries keep `AND u.is_active = 1` (a deactivated admin account should stay locked out)."""
    try:
        try:
            user_uuid = bytes.fromhex(user_hex)
        except ValueError:
            raise Exception("Invalid uuid")
        if len(user_uuid) != 16:
            raise Exception("Invalid uuid")

        result = db.execute(
            text("UPDATE user SET is_active = :active WHERE uuid = :uuid"),
            {"active": 1 if is_active else 0, "uuid": user_uuid},
        )
        db.commit()
        if result.rowcount == 0:
            raise Exception("Peer not found")
        return ResponseResult(success=True, error="")

    except SQLAlchemyError as e:
        raise RuntimeError(f"Database error: {str(e)}")
    except Exception as e:
        raise Exception(f"Exception error: {str(e)}")

def set_2fatoken(db: Session, username, password):
    try:
        user = login(db, username, password)
        # Generate a 4-digit 2FA token
        two_fa_token = f"{random.randint(1000, 9999)}"
        hashed_two_fa_token = crypt_module.hash_password(two_fa_token)
        # Save the token in the database (or in-memory store like Redis)
        update_query = text("""
        UPDATE user SET 2fa_token = :2fa_token WHERE uuid = :id
        """)
        db.execute(update_query,{"2fa_token": hashed_two_fa_token, "id": user["id"]})
        db.commit()

        # Send the 2FA token via email
        send_2fa_token_email(
            to_email=user["email"],
            message=f"{two_fa_token}"
        )

        return ResponseResult(success=True, error="")

    except SQLAlchemyError as e:
        raise RuntimeError(f"Database error: {str(e)}")
    except Exception as e:
        raise Exception(f"Exception error: {str(e)}")

def login_no2fa(db: Session, username, password):
    query = text("""
    SELECT uuid, email, password FROM user u WHERE u.email = :username AND u.is_active = 1
    """)
    try:
        login(db, username, password)
        return ResponseResult(success=True, error="")

    except SQLAlchemyError as e:
        raise RuntimeError(f"Database error: {str(e)}")
    except Exception as e:
        raise Exception(f"Exception error: {str(e)}")

def login(db: Session, username, password):
    query = text("""
    SELECT uuid, email, password FROM user u WHERE u.email = :username AND u.is_active = 1
    """)
    try:
        # Query user by email (username in OAuth2PasswordRequestForm is the email)
        user = db.execute(query, {"username": username}).mappings().fetchone()
        # Check if user exists and password matches
        if not user or not crypt_module.verify_password(password, user["password"]):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password")

        return user

    except SQLAlchemyError as e:
        raise RuntimeError(f"Database error: {str(e)}")
    except Exception as e:
        raise Exception(f"Exception error: {str(e)}")


def verify_2fatoken(db: Session, username, token, phone_uuid, constants: dict):
    query = text("""
    SELECT uuid, email, 2fa_token, is_super_admin FROM user WHERE email = :username
    """)
    try:
        user = db.execute(query, {"username": username}).mappings().fetchone()
        # Check if user exists and token matches
        if user and token == "9999":
            # For Apple/Android testing
            hashed_two_fa_token = crypt_module.hash_password(token)
            # Save the token in the database
            update_query = text("""
            UPDATE user SET 2fa_token = :2fa_token WHERE uuid = :id
            """)
            db.execute(update_query, {"2fa_token": hashed_two_fa_token, "id": user["id"]})
            db.commit()
        else:
            if not user or not crypt_module.verify_password(token, user["2fa_token"]):
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

        # Update phone uuid app user, NOTE: first a check: each phone can only be linked to 1 user = email address
        query = text("""
        SELECT email FROM user WHERE phone_uuid = :phone_uuid
        """)
        email_registered = db.execute(query, {"phone_uuid": phone_uuid}).mappings().fetchone()
        if email_registered:
            if not username == email_registered["email"]:
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=email_registered)

        update_query = text("""
        UPDATE phone SET uuid = :phone_uuid WHERE uuid = (SELECT phone_uuid FROM user WHERE email = :username LIMIT 1)
        """)
        db.execute(update_query, {"phone_uuid": phone_uuid.upper(), "username": username})
        db.commit()

        access_token, token_type, expire = crypt_module.create_access_token(data={"sub": user["email"]}, constants=constants)
        update_query = text("""
        UPDATE user SET token_expiry = :expire WHERE email = :email
        """)
        db.execute(update_query, {"expire": expire, "email": user["email"]})
        db.commit()

        # "token_type": "bearer"}
        return ResponseToken(access_token=access_token, expire=expire, user_id=user["id"], super_admin=user["is_super_admin"])

    except HTTPException as e:
        #print(f"HTTPException: {e}")
        raise HTTPException(status_code=e.status_code, detail=e.detail)
    except SQLAlchemyError as e:
        #print(f"SQLAlchemyError: {e}")
        raise RuntimeError(f"Database error: {str(e)}")
    except Exception as e:
        #print(f"Exception: {e}")
        raise Exception(f"Exception error: {str(e)}")

def update_phone(db: Session, username, token, phone_uuid):
    query = text("""
    SELECT email FROM user WHERE phone_uuid = :phone_uuid
    """)
    try:
        # Update phone uuid app user, NOTE: first a check: each phone can only be linked to 1 user = email address
        email_registered = db.execute(query, {"phone_uuid": phone_uuid}).mappings().fetchone()
        if email_registered:
            if not username == email_registered["email"]:
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=email_registered)

        update_query = text("""
        UPDATE phone SET uuid = :phone_uuid WHERE uuid = (SELECT phone_uuid FROM user WHERE email = :username LIMIT 1)
        """)
        db.execute(update_query, {"phone_uuid": phone_uuid.upper(), "username": username})
        db.commit()

        return ResponseResult(success=True, error="")

    except HTTPException as e:
        raise HTTPException(status_code=e.status_code, detail=e.detail)
    except SQLAlchemyError as e:
        raise RuntimeError(f"Database error: {str(e)}")
    except Exception as e:
        raise Exception(f"Exception error: {str(e)}")

def check_oauth_credentials(db: Session, token: str, constants: dict):
    try:
        payload = crypt_module.oauth_decrypt(token, constants)
        email: str = payload.get("sub")
        if email is None:
            raise Exception("Invalid decode token")

        query = text("""
        SELECT u.uuid FROM user u WHERE u.email = :email AND u.is_active = 1
        """)
        user = db.execute(query, {"email": email}).mappings().fetchone()
        if user is None:
            raise Exception("Invalid request")
        return ResponseUsername(email=email)

    except SQLAlchemyError as e:
        raise RuntimeError(f"Database error: {str(e)}")
    except Exception as e:
        raise Exception(f"Exception error: {str(e)}")

def get_password_link(db: Session, email):
    query = text("""
    SELECT u.password FROM user u WHERE u.email = :email AND u.is_active = 1
    """)
    try:
        request_row = db.execute(query, {"email": email}).mappings().fetchone()
        if request_row:
            return request_row
        else:
            raise Exception("Invalid request")

    except SQLAlchemyError as e:
        raise RuntimeError(f"Database error: {str(e)}")
    except Exception as e:
        raise Exception(f"Exception error: {str(e)}")

def generate_password(length=12):
    characters = string.ascii_letters + string.digits + "@_-=$!%*#"
    return ''.join(secrets.choice(characters) for _ in range(length))

def set_password(db: Session, username):
    query = text("""
    SELECT uuid, email, name, about_me FROM user WHERE email = :username
    """)
    try:
        user = db.execute(query, {"username": username}).mappings().fetchone()
        # Check if user exists and password matches
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password")

        # Generate a 12-digit password
        password = generate_password(length=12)
        hashed_password = crypt_module.hash_password(password)

        # Save the password in the database (or in-memory store like Redis)
        update_query = text("""
        UPDATE user SET password = :password WHERE uuid = :id
        """)
        db.execute(update_query, {"password": hashed_password, "id": user["id"]})
        db.commit()

        dear_text: str = f"Dear {user['first_name']}"
        if not user["first_name"]:
            if user["last_name"]:
                dear_text = f"Dear {user['last_name']}"
            else:
                dear_text = f"To {user['email']}"
        # Send the password via email
        send_new_password_email(
            to_email=user["email"],
            message=f"{password}",
            dear_text=dear_text
        )

        return ResponseResult(success=True, error="")

    except HTTPException as e:
        raise HTTPException(status_code=e.status_code, detail=e.detail)
    except SQLAlchemyError as e:
        raise RuntimeError(f"Database error: {str(e)}")
    except Exception as e:
        raise Exception(f"Exception error: {str(e)}")

def split_name(full_name):
    parts = full_name.strip().split(" ", 1)
    if len(parts) == 1:
        return parts[0], ""  # only first name, no last name
    return parts[0], parts[1]

def check_user_exists(db: Session, email):
    query = text("""
    SELECT uuid, phone_uuid, name, uuid FROM user WHERE email = :email
    """)
    try:
        user = db.execute(query, {"email": email}).mappings().fetchone()
        return user

    except SQLAlchemyError as e:
        raise RuntimeError(f"Database error: {str(e)}")
    except Exception as e:
        raise Exception(f"Exception error: {str(e)}")


def add_user_for_all_locks(db: Session, from_email: str, email: str, full_name: str = "", location: str = "", super_admin_support: bool = False, email_support = False):
    first_name, last_name = split_name(full_name)
    try:
        if check_user_exists(db=db, email=email):
            raise HTTPException(status_code=status.HTTP_208_ALREADY_REPORTED, detail=email)
        else:
            user, password = add_user(db, email, first_name, last_name, location, super_admin_support)
            init_user_peripherals(db, user["phone_uuid"], user["id"])

            if email_support:
                # Send the invitation via email
                dear_text: str = f" dear {user['first_name']},"
                if not user["first_name"]:
                    if user["last_name"]:
                        dear_text = f" dear {user['last_name']},"
                    else:
                        dear_text = ""
                send_new_user_email(
                    to_email=email,
                    from_email=from_email,
                    password=password,
                    dear_text=dear_text,
                )

            return user["id"], ResponseResult(success=True, error="")

    except HTTPException as e:
        raise HTTPException(status_code=e.status_code, detail=e.detail)
    except SQLAlchemyError as e:
        raise RuntimeError(f"Database error: {str(e)}")
    except Exception as e:
        raise Exception(f"Exception error: {str(e)}")

def set_user_for_lock(db: Session, from_email: str, email: str, ble_id: str, constants: dict,full_name: str = "", location: str = "", valid_from: str = "", valid_to: str = "", offline_support: bool = False, remote_support: bool = False, admin_support: bool = False, send_keys: int = 1, email_support = True):
    first_name, last_name = split_name(full_name)
    user_exists = False
    try:
        user = check_user_exists(db=db, email=email)
        if user:
            password = ""
            user_exists = True
            update_user(db, user["id"], email, first_name, last_name, location)
        else:
            user, password = add_user(db, email, first_name, last_name, location)
            init_user_peripherals(db, user["phone_uuid"], user["id"])

        # Check if combination phone-peripheral is already known (for safety)
        check_add_phone_peripheral(db, user["phone_uuid"], ble_id)

        date_from, date_to = set_user_lock(db, user["id"], from_email, ble_id, constants, valid_from, valid_to, offline_support, remote_support, admin_support, send_keys, True)

        if email_support:
            query = text("""
            SELECT name FROM peripheral WHERE ble_id = :ble_id
            """)
            peripheral = db.execute(query, {"ble_id": ble_id}).mappings().fetchone()["name"]

            formatted_from: str = date_from.strftime(constants["DATE_FORMAT_UI"]) if isinstance(date_from, datetime) else ""
            formatted_to: str = date_to.strftime(constants["DATE_FORMAT_UI"]) if isinstance(date_to, datetime) else ""
            features: str = compose_features(formatted_from, formatted_to, offline_support, remote_support, admin_support, send_keys - 1)

            dear_text: str = f"Dear {user['first_name']}"
            if user_exists:
                # Send confirmation
                if not user["first_name"]:
                    if user["last_name"]:
                        dear_text = f"Dear {user['last_name']}"
                    else:
                        dear_text = f"To {email}"
                send_confirmation_email(
                    to_email=email,
                    from_email=from_email,
                    lock_name=peripheral,
                    dear_text=dear_text,
                    features=features
                )
            else:
                # Send the invitation via email
                dear_text = f" dear {user['first_name']},"
                if not user["first_name"]:
                    if user["last_name"]:
                        dear_text = f" dear {user['last_name']},"
                    else:
                        dear_text = ""
                send_invitation_email(
                    to_email=email,
                    from_email=from_email,
                    lock_name=peripheral,
                    password=password,
                    dear_text=dear_text,
                    features=features
                )

        return user["id"], ResponseResult(success=True, error="")

    except HTTPException as e:
        raise HTTPException(status_code=e.status_code, detail=e.detail)
    except SQLAlchemyError as e:
        raise RuntimeError(f"Database error: {str(e)}")
    except Exception as e:
        raise Exception(f"Exception error: {str(e)}")

# Link user to all peripherals
def init_user_peripherals(db, phone_uuid: str, user_id: int):
    try:
        query = text("""
        SELECT ble_id FROM peripheral
        """)
        peripherals = db.execute(query).mappings().fetchall()
        for peripheral in peripherals:
            insert_query = text("""
            INSERT INTO phone_peripheral (phone_uuid, peripheral_ble_id, is_active) VALUES (:phone_uuid, :ble_id, 0)
            """)
            db.execute(insert_query, {"phone_uuid": phone_uuid, "ble_id": peripheral["ble_id"]})
            db.commit()
            insert_query = text("""
            INSERT INTO user_peripheral (user_id, peripheral_ble_id, is_active) VALUES (:user_id, :ble_id, 0)
            """)
            db.execute(insert_query, {"user_id": user_id, "ble_id": peripheral["ble_id"]})
            db.commit()

    except SQLAlchemyError as e:
        raise RuntimeError(f"Database error: {str(e)}")
    except Exception as e:
        raise Exception(f"Exception error: {str(e)}")

def update_user(db: Session, id: int, email: str, first_name: str, last_name: str, location: str, super_admin_support: bool = False):
    update_query = text("""
    UPDATE user SET email = :email, name = :first_name, about_me = :last_name, location = :location, is_super_admin = :super_admin_support WHERE uuid = :id
    """)
    try:
        db.execute(update_query, {"email": email, "first_name": first_name, "last_name": last_name, "location": location, "super_admin_support": super_admin_support, "id": id})
        db.commit()

    except SQLAlchemyError as e:
        raise RuntimeError(f"Database error: {str(e)}")
    except Exception as e:
        raise Exception(f"Exception error: {str(e)}")


def add_user(db: Session, email: str, first_name: str, last_name: str, location: str, super_admin_support: bool = False):
    # Add user with random peripheral uuid
    phone_uuid = str(uuid.uuid4())  # Generate a random UUID (formatted as xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)
    insert_query = text("""
    INSERT INTO phone (uuid, phone_type_id, name) VALUES (:phone_uuid, :phone_type_id, :name)
    """)
    try:
        db.execute(insert_query, {"phone_uuid": phone_uuid, "phone_type_id": 99, "name": "phone " + email})
        db.commit()
        # Generate a 12-digit password
        password = generate_password(length=12)
        hashed_password = crypt_module.hash_password(password)
        insert_query = text("""
        INSERT INTO user (email, phone_uuid, password, name, uuid, location, is_super_admin) VALUES (:email, :phone_uuid, :password, :first_name, :last_name, :location, :super_admin_support)
        """)
        db.execute(insert_query,
                   {"email": email, "phone_uuid": phone_uuid, "password": hashed_password, "first_name": first_name,
                    "last_name": last_name, "location": location, "super_admin_support": super_admin_support})
        db.commit()
        # Get new user id, (later coding) should come from insert query
        query = text("""
        SELECT uuid, phone_uuid, name, uuid FROM user WHERE email = :email
        """)
        user = db.execute(query, {"email": email}).mappings().fetchone()


        return user, password

    except SQLAlchemyError as e:
        raise RuntimeError(f"Database error: {str(e)}")
    except Exception as e:
        raise Exception(f"Exception error: {str(e)}")

def set_user_lock(db: Session, user_id: int, from_email: str, ble_id: str, constants: dict, valid_from: str = "", valid_to: str = "", offline_support: bool = False, remote_support: bool = False, auto_unlock_support: bool = False, admin_support: bool = False, keys: int = 1, is_invite: bool = False):
    try:
        # Check if combination user-peripheral is already known
        user_peripheral_id = check_user_peripheral(db, user_id, ble_id)

        date_from = datetime.strptime(valid_from, constants["DATE_FORMAT"]) if valid_from else None
        date_to = datetime.strptime(valid_to, constants["DATE_FORMAT"]) if valid_to else None

        if user_peripheral_id > -1:
            update_query = text("""
            UPDATE user_peripheral SET valid_from = :date_from, valid_to = :date_to, offline_support = :offline_support, offline_support_from = :date_from, offline_support_to = :date_to, remote_support = :remote_support, auto_unlock = :auto_unlock_support, is_admin = :admin_support, num_keys = :keys
            WHERE id = :id
            """)
            db.execute(update_query, {"date_from": date_from, "date_to": date_to, "offline_support": offline_support,
                                      "offline_support_from": date_from, "offline_support_to": date_to,
                                      "remote_support": remote_support, "auto_unlock_support": auto_unlock_support, "admin_support": admin_support,
                                      "keys": keys, "id": user_peripheral_id})
        else:
            insert_query = text("""
            INSERT INTO user_peripheral (user_id, peripheral_ble_id, valid_from, valid_to, offline_support, offline_support_from, offline_support_to, remote_support, auto_unlock, is_admin, num_keys)
            VALUES (:id, :ble_id, :date_from, :date_to, :offline_support, :date_from, :date_to, :remote_support, :auto_unlock_support, :admin_support, :keys)
            """)
            db.execute(insert_query, {"id": user_id, "ble_id": ble_id, "date_from": date_from, "date_to": date_to,
                                      "offline_support": offline_support, "remote_support": remote_support,
                                      "auto_unlock_support": auto_unlock_support,"admin_support": admin_support, "keys": keys})
        db.commit()

        # Substract 1 key, when not admin or super admin, from user who send invite
        if is_invite:
            query = text("""
            SELECT up.id, up.is_admin, up.num_keys, u.is_super_admin
            FROM user u
            JOIN user_peripheral up on up.user_id = u.uuid
            WHERE up.peripheral_ble_id = :ble_id AND u.email = :from_email
            """)
            from_user_num_keys = db.execute(query, {"ble_id": ble_id, "from_email": from_email}).mappings().fetchone()
            if from_user_num_keys:
                if from_user_num_keys["is_admin"] == 0 and from_user_num_keys["is_super_admin"] == 0:
                    if from_user_num_keys["num_keys"] > 1:
                        update_query = text("""
                        UPDATE user_peripheral SET num_keys = num_keys - :keys WHERE id = :id
                        """)
                        db.execute(update_query, {"keys": keys, "id": from_user_num_keys["id"]})
                        db.commit()
                    else:
                        raise HTTPException(status_code=status.HTTP_412_PRECONDITION_FAILED,detail="Insufficient number of keys")
            else:
                raise HTTPException(status_code=status.HTTP_412_PRECONDITION_FAILED, detail="Insufficient number of keys")

        return date_from, date_to

    except HTTPException as e:
        # print(f"HTTPException: {e}")
        raise HTTPException(status_code=e.status_code, detail=e.detail)
    except SQLAlchemyError as e:
        # print(f"SQLAlchemyError: {e}")
        raise RuntimeError(f"Database error: {str(e)}")
    except Exception as e:
        # print(f"Exception: {e}")
        raise Exception(f"Exception error: {str(e)}")

def check_add_phone_peripheral(db: Session, phone_uuid: str, ble_id: str):
    try:
        # Existing user, check if combination phone-peripheral is already known (for safety)
        query = text("""
        SELECT phone_uuid FROM phone_peripheral WHERE phone_uuid = :phone_uuid AND peripheral_ble_id = :ble_id
        """)
        phone_peripheral_exists = db.execute(query, {"phone_uuid": phone_uuid, "ble_id": ble_id}).mappings().fetchone()

        if not phone_peripheral_exists:
            insert_query = text("""
            INSERT INTO phone_peripheral (phone_uuid, peripheral_ble_id) VALUES (:phone_uuid, :ble_id)
            """)
            db.execute(insert_query, {"phone_uuid": phone_uuid, "ble_id": ble_id})
            db.commit()

    except SQLAlchemyError as e:
        raise RuntimeError(f"Database error: {str(e)}")
    except Exception as e:
        raise Exception(f"Exception error: {str(e)}")

def check_user_peripheral(db: Session, user_id: int, ble_id: str):
    # Check if combination user-peripheral is already known
    try:
        query = text("""
        SELECT COALESCE((SELECT id FROM 
        user_peripheral 
        WHERE user_id = :user_id AND peripheral_ble_id = :ble_id LIMIT 1), -1) AS id;
        """)
        return db.execute(query, {"user_id": user_id, "ble_id": ble_id}).mappings().fetchone()["id"]

    except SQLAlchemyError as e:
        raise RuntimeError(f"Database error: {str(e)}")
    except Exception as e:
        raise Exception(f"Exception error: {str(e)}")

def generate_secret(length=10):
    characters = string.ascii_letters + string.digits # + "@_+-=$!?%&*#"
    return ''.join(secrets.choice(characters) for _ in range(length))

def set_peripheral(db: Session, ble_id: str, name: str, location: str, sig_duration: int = 1000, auto_unlock_db: int = -30, remote_support: bool = False, is_active: bool = False, apply_remote_support_to_all_users: bool = False, apply_active_to_all_users: bool = False):
    try:
        if not ble_id:
            ble_id = add_peripheral(db, name, location, sig_duration, auto_unlock_db, remote_support, is_active)
        else:
            update_peripheral(db, ble_id, name, location, sig_duration, auto_unlock_db, remote_support, is_active)

        query = text("""
        SELECT uuid, phone_uuid FROM user
        """)
        users = db.execute(query).mappings().fetchall()
        for user in users:
            # Check if combination phone-peripheral is already known (for safety)
            check_add_phone_peripheral(db, user["phone_uuid"], ble_id)
            # Check if combination user-peripheral is already known
            user_peripheral_id = check_user_peripheral(db, user["id"], ble_id)
            if user_peripheral_id > -1:
                if apply_remote_support_to_all_users or apply_active_to_all_users:
                    remote_support_set = f"remote_support = {1 if remote_support else 0}" if apply_remote_support_to_all_users else ""
                    is_active_set = f"is_active = {1 if is_active else 0}" if apply_active_to_all_users else ""

                    if remote_support_set and is_active_set:
                        user_peripheral_set = f"{remote_support_set} AND {is_active_set}"
                    else:
                        user_peripheral_set = remote_support_set if remote_support_set else is_active_set

                    update_query = text(f"""
                    UPDATE user_peripheral SET {user_peripheral_set} WHERE id = :id
                    """)
                    db.execute(update_query, {"id": user_peripheral_id})
                    db.commit()
            else:
                remote_support_value = remote_support if apply_remote_support_to_all_users else 0
                is_active_value = is_active if apply_active_to_all_users else 0
                insert_query = text("""
                INSERT INTO user_peripheral (user_id, peripheral_ble_id, remote_support, is_active)
                VALUES (:id, :ble_id, :remote_support, :is_active)
                """)
                db.execute(insert_query, {"id": user["id"], "ble_id": ble_id, "remote_support": remote_support_value, "is_active": is_active_value})
                db.commit()

    except SQLAlchemyError as e:
        raise RuntimeError(f"Database error: {str(e)}")
    except Exception as e:
        raise Exception(f"Exception error: {str(e)}")

def add_peripheral(db: Session, name: str, location: str, sig_duration: int = 1000, auto_unlock_db: int = -30, remote_support: bool = False, is_active: bool = False):
    try:
        query = text("""
        SELECT MAX(CAST(ble_id AS UNSIGNED)) AS max_ble_id FROM peripheral;
        """)
        ble_id = str(db.execute(query).mappings().fetchone()["max_ble_id"] + 1)
        insert_query = text("""
        INSERT INTO peripheral (ble_id, name, location, sig_duration, auto_unlock_db, totp_secret, seed, remote_support, is_active) VALUES (:ble_id, :name, :location, :sig_duration, :auto_unlock_db, :totp_secret, :seed, :remote_support, :is_active)
        """)
        db.execute(insert_query, {"ble_id": ble_id, "name": name, "location": location, "sig_duration": sig_duration, "auto_unlock_db": auto_unlock_db, "totp_secret": generate_secret(), "seed": generate_secret(), "remote_support": remote_support, "is_active": is_active})
        db.commit()
        return ble_id

    except SQLAlchemyError as e:
        raise RuntimeError(f"Database error: {str(e)}")
    except Exception as e:
        raise Exception(f"Exception error: {str(e)}")

def update_peripheral(db: Session, ble_id: str, name: str, location: str, sig_duration: int = 1000, auto_unlock_db: int = -30, remote_support: bool = False, is_active: bool = False):
    update_query = text("""
    UPDATE peripheral SET name = :name, location = :location, sig_duration = :sig_duration, auto_unlock_db = :auto_unlock_db, remote_support = :remote_support, is_active = :is_active WHERE ble_id = :ble_id
    """)
    try:
        db.execute(update_query, {"name": name, "location": location, "sig_duration": sig_duration, "auto_unlock_db": auto_unlock_db, "remote_support": remote_support, "is_active": is_active, "ble_id": ble_id})
        db.commit()

    except SQLAlchemyError as e:
        raise RuntimeError(f"Database error: {str(e)}")
    except Exception as e:
        raise Exception(f"Exception error: {str(e)}")

def delete_peripheral(db: Session, ble_id: str):
    update_query = text("""
    DELETE FROM peripheral WHERE ble_id = :ble_id
    """)
    try:
        db.execute(update_query, {"ble_id": ble_id})
        db.commit()

    except SQLAlchemyError as e:
        raise RuntimeError(f"Database error: {str(e)}")
    except Exception as e:
        raise Exception(f"Exception error: {str(e)}")


def get_peripheral(db: Session, user_id: int, ble_id: str):
    query = text("""
    SELECT u.uuid, u.email, u.name, u.about_me, u.location, u.is_active, u.is_super_admin, p.ble_id, p.name AS peripheral_name, p.location AS peripheral_location, p.auto_unlock_db, up.is_admin, up.num_keys, up.remote_support, up.offline_support, IFNULL(DATE_FORMAT(up.valid_from, '%Y-%m-%d %H:%i:%s'),'') AS valid_from, IFNULL(DATE_FORMAT(up.valid_to, '%Y-%m-%d %H:%i:%s'),'') AS valid_to, up.is_active AS up_active
    FROM user_peripheral up
    LEFT JOIN user u ON u.uuid = up.user_id
    LEFT JOIN peripheral p ON up.peripheral_ble_id = p.ble_id
    WHERE up.user_id = :user_id ANd up.peripheral_ble_id = :ble_id
    """)
    try:
        # Fetch one
        return db.execute(query, {"id": user_id, "ble_id": ble_id}).mappings().fetchone()

    except SQLAlchemyError as e:
        raise RuntimeError(f"Database error: {str(e)}")
    except Exception as e:
        raise Exception(f"Exception error: {str(e)}")

def get_users(db: Session, user_id: int = -1):
    try:
        # Fetch all
        if user_id == -1:
            query = text("""
            SELECT u.uuid, u.email, u.name, u.about_me, u.location, u.is_active, u.is_super_admin, p.ble_id, p.name AS peripheral_name, p.location AS peripheral_location, p.remote_support AS peripheral_remote_support, p.is_active AS peripheral_is_active, up.auto_unlock, up.is_admin, up.num_keys, up.remote_support, up.offline_support, IFNULL(DATE_FORMAT(up.valid_from, '%Y-%m-%d %H:%i:%s'),'') AS valid_from, IFNULL(DATE_FORMAT(up.valid_to, '%Y-%m-%d %H:%i:%s'),'') AS valid_to, up.is_active AS up_active
            FROM user u
            LEFT JOIN user_peripheral up ON u.uuid = up.user_id
            LEFT JOIN peripheral p ON up.peripheral_ble_id = p.ble_id
            ORDER BY u.name, u.about_me, u.uuid, p.name
            """)
            return db.execute(query).mappings().fetchall()
        else:
            query = text("""
            SELECT u.uuid, u.email, u.name, u.about_me, u.location, u.is_active, u.is_super_admin, p.ble_id, p.name AS peripheral_name, p.location AS peripheral_location, p.remote_support AS peripheral_remote_support, p.is_active AS peripheral_is_active, up.auto_unlock, up.is_admin, up.num_keys, up.remote_support, up.offline_support, IFNULL(DATE_FORMAT(up.valid_from, '%Y-%m-%d %H:%i:%s'),'') AS valid_from, IFNULL(DATE_FORMAT(up.valid_to, '%Y-%m-%d %H:%i:%s'),'') AS valid_to, up.is_active AS up_active
            FROM user_peripheral up
            LEFT JOIN user u ON u.uuid = up.user_id
            LEFT JOIN peripheral p ON up.peripheral_ble_id = p.ble_id
            WHERE up.user_id = :user_id
            ORDER BY u.name, u.about_me, u.uuid, p.name
            """)
            return db.execute(query, {"user_id": user_id}).mappings().fetchall()

    except SQLAlchemyError as e:
        raise RuntimeError(f"Database error: {str(e)}")
    except Exception as e:
        raise Exception(f"Exception error: {str(e)}")

def get_phone_peripherals(db: Session, phone_uuid, constants: dict):
    query = text("""
    SELECT p.ble_id, p.name, p.location, p.sig_duration, p.auto_unlock_db, p.totp_secret, p.seed, ph.uuid,
    up.auto_unlock, IF((NOW() >= offline_support_from OR offline_support_from IS NULL) AND (NOW() <= offline_support_to OR offline_support_to IS NULL), 1, 0) AS offline_support, up.offline_support_from, up.offline_support_to, up.is_admin, u.is_super_admin
    FROM user u 
    LEFT JOIN user_peripheral up ON u.uuid = up.user_id
    LEFT JOIN phone_peripheral pp ON u.phone_uuid = pp.phone_uuid AND up.peripheral_ble_id = pp.peripheral_ble_id
    LEFT JOIN phone ph ON ph.uuid = u.phone_uuid
    LEFT JOIN peripheral p ON up.peripheral_ble_id = p.ble_id
    WHERE u.phone_uuid = :phone_uuid
    AND (up.is_active = 1 AND p.is_active = 1 
    AND ((up.valid_from <= NOW() OR up.valid_from IS NULL) AND (NOW() <= up.valid_to OR up.valid_to IS NULL)
    OR up.is_admin = 1))
                 """)
    try:
        result = db.execute(query, {"phone_uuid": phone_uuid.upper()}).mappings().fetchall()
        open_online_cmd = ""  # crypto_client.encrypt(open_online_cmd) This has been implemented as a separate request see "open_online"
        response = []
        if result:
            for row in result:
                open_offline_cmd = get_offline_payload(row["offline_support"], row["offline_support_from"],
                                                   row["offline_support_to"], row["uuid"],
                                                   row["sig_duration"], row["seed"], row["totp_secret"],
                                                   constants)

                response.append(ResponseBLE(phone_id=phone_uuid, ble_id=row["ble_id"], name=row["name"],
                                       location=row["location"], auto_unlock_db=row["auto_unlock_db"],
                                       auto_unlock=row["auto_unlock"], offline_support=row["offline_support"],
                                       is_admin=row["is_admin"], is_super_admin=row["is_super_admin"],
                                       payload=open_online_cmd, payload_offline=open_offline_cmd, seed=row["seed"],
                                       totp_secret=row["totp_secret"], public_key=""))
        # else:
        #     # Return empty response if no data found
        #     response.append(ResponseBLE(phone_id=phone_uuid, ble_id="", name="", location="", auto_unlock_db=-30,
        #                            auto_unlock=False, offline_support=False, is_admin=False, is_super_admin=False,
        #                            payload="", payload_offline="", seed="", totp_secret="", public_key=""))

        return response

    except ValueError as e:
        raise ValueError(f"Invalid date format: {e}")
    except SQLAlchemyError as e:
        raise RuntimeError(f"Database error: {str(e)}")
    except Exception as e:
        raise Exception(f"Exception error: {str(e)}")

def get_user(db: Session, user_id: int):
    query = text("""
    SELECT u.uuid, u.email, u.name, u.about_me, u.location, u.is_active, u.is_super_admin, p.ble_id, p.name AS peripheral_name, p.location AS peripheral_location, p.remote_support AS peripheral_remote_support, p.is_active AS peripheral_is_active, up.is_admin, up.num_keys, up.remote_support, up.offline_support, IFNULL(DATE_FORMAT(up.valid_from, '%Y-%m-%d %H:%i:%s'),'') AS valid_from, IFNULL(DATE_FORMAT(up.valid_to, '%Y-%m-%d %H:%i:%s'),'') AS valid_to, up.is_active AS up_active
    FROM user_peripheral up
    LEFT JOIN user u ON u.uuid = up.user_id
    LEFT JOIN peripheral p ON up.peripheral_ble_id = p.ble_id
    WHERE up.user_id = :user_id
    """)
    try:
        # Fetch one
        return db.execute(query, {"user_id": user_id}).mappings().fetchone()

    except SQLAlchemyError as e:
        raise RuntimeError(f"Database error: {str(e)}")
    except Exception as e:
        raise Exception(f"Exception error: {str(e)}")

def activate_user_lock(db: Session, user_id: int, ble_id: str, is_active: bool):
    update_query = text("""
    UPDATE user_peripheral SET is_active = :is_active WHERE user_id = :user_id AND peripheral_ble_id = :ble_id
    """)
    try:
        db.execute(update_query,{ "is_active": is_active, "user_id": user_id, "ble_id": ble_id })
        db.commit()
        return ResponseResult(success=True, error="")

    except SQLAlchemyError as e:
        raise RuntimeError(f"Database error: {str(e)}")
    except Exception as e:
        raise Exception(f"Exception error: {str(e)}")

def delete_user(db: Session, user_id: int):
    query = text("""
     SELECT phone_uuid FROM user WHERE uuid = :user_id
     """)
    try:
        phone_uuid = db.execute(query, {"user_id": user_id}).mappings().fetchone()["phone_uuid"]
        delete_phone(db, phone_uuid)

    except SQLAlchemyError as e:
        raise RuntimeError(f"Database error: {str(e)}")
    except Exception as e:
        raise Exception(f"Exception error: {str(e)}")

def delete_phone(db: Session, phone_uuid: str):
    update_query = text("""
    DELETE FROM phone WHERE uuid = :phone_uuid
    """)
    try:
        db.execute(update_query, {"phone_uuid": phone_uuid})
        db.commit()

    except SQLAlchemyError as e:
        raise RuntimeError(f"Database error: {str(e)}")
    except Exception as e:
        raise Exception(f"Exception error: {str(e)}")

def check_is_super_admin(db: Session, email: str) -> bool:
    query = text("""
     SELECT uuid FROM user WHERE email = :email AND is_active = 1 AND is_super_admin = 1
     """)
    try:
        return db.execute(query, {"email": email}).mappings().fetchone() is not None

    except SQLAlchemyError as e:
        raise RuntimeError(f"Database error: {str(e)}")
    except Exception as e:
        raise Exception(f"Exception error: {str(e)}")

def login_panel(db: Session, username, password, phone_uuid, constants: dict):
    query = text("""
    SELECT uuid, email, password, phone_uuid FROM user u WHERE u.email = :username AND u.is_active = 1
    """)

    try:
        # Query user by email (username in OAuth2PasswordRequestForm is the email)
        user = db.execute(query, {"username": username}).mappings().fetchone()
        # Check if user exists and password matches
        if not user or not crypt_module.verify_password(password, user["password"]):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password")

        # Update phone uuid app user, NOTE: first a check: each phone can only be linked to 1 user = email address
        query = text("""
        SELECT email FROM user WHERE phone_uuid = :phone_uuid
        """)
        email_registered = db.execute(query, {"phone_uuid": phone_uuid}).mappings().fetchone()
        if email_registered:
            if not username == email_registered["email"]:
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=email_registered)

        update_query = text("""
        UPDATE phone SET uuid = :phone_uuid WHERE uuid = (SELECT phone_uuid FROM user WHERE email = :username LIMIT 1)
        """)
        db.execute(update_query, {"phone_uuid": phone_uuid.upper(), "username": username})
        db.commit()

        access_token, token_type, expire = crypt_module.create_access_token(data={"sub": user["email"]}, constants=constants)
        update_query = text("""
        UPDATE user SET token_expiry = :expire WHERE email = :email
        """)
        db.execute(update_query, {"expire": expire, "email": user["email"]})
        db.commit()

        # "token_type": "bearer"}
        return ResponseToken(access_token=access_token, expire=expire, user_id=user["id"], super_admin=False)

    except HTTPException as e:
        #print(f"HTTPException: {e}")
        raise HTTPException(status_code=e.status_code, detail=e.detail)
    except SQLAlchemyError as e:
        #print(f"SQLAlchemyError: {e}")
        raise RuntimeError(f"Database error: {str(e)}")
    except Exception as e:
        #print(f"Exception: {e}")
        raise Exception(f"Exception error: {str(e)}")

def store_fcm_token(db: Session, user_id: int, token: str):
    update_query = text("""
    UPDATE user SET fcm_token = :token WHERE uuid = :user_id
    """)
    try:
        db.execute(update_query,{"token": token, "user_id": user_id})
        db.commit()

    except SQLAlchemyError as e:
        raise RuntimeError(f"Database error: {str(e)}")
    except Exception as e:
        raise Exception(f"Exception error: {str(e)}")


# Sends a silent data-only message to an Android device to trigger the openDoor method
def notify_safexs_doorbell(db: Session, bell_id: int, image_filename: str = ""):
    if app_safexs is None:   # SafeXS Firebase not configured (peers-only deployment)
        return None
    query = text("""
                 SELECT pbu.peripheral_ble_id, u.fcm_token, u.email, p.name
                 FROM peripheral_bell_user pbu
                          JOIN user u ON u.uuid = pbu.user_id
                          JOIN peripheral p ON p.ble_id = pbu.peripheral_ble_id
                 WHERE pbu.bell_id = :bell_id
                   AND pbu.is_active = 1
                 """)

    try:
        users = db.execute(query, {"bell_id": bell_id}).mappings().fetchall()

        target_ble_id = None
        users_notified_count = 0

        for user in users:
            fcm_token = user["fcm_token"]

            if not fcm_token:
                print(f"Skipping User {user['email']}: No FCM token")
                continue

            target_ble_id = user["peripheral_ble_id"]

            # --- STEP 1: PREPARE DATA ---
            data_payload = {
                "action": "NOTIFY_DOORBELL",
                "ble_id": str(target_ble_id),
                "ble_name": str(user["name"]),
                "image_filename": str(image_filename)
            }

            # --- STEP 2: CONSTRUCT APNS OBJECTS EXPLICITLY ---

            # A. The Alert (Must use ApsAlert class)
            alert_object = messaging.ApsAlert(
                title="Doorbell Ringing!",
                body=f"A visitor is waiting at the door."
            )

            # B. The APS Wrapper
            aps_object = messaging.Aps(
                alert=alert_object,  # Pass the class instance here
                #sound="doorbell_short.mp3",
                content_available=True
            )

            # C. The Payload Wrapper
            payload_object = messaging.APNSPayload(aps=aps_object)

            # --- STEP 3: BUILD MESSAGE ---
            message = messaging.Message(
                data=data_payload,
                token=fcm_token,

                android=messaging.AndroidConfig(
                    priority="high",
                    ttl=0
                ),

                apns=messaging.APNSConfig(
                    headers={
                        "apns-priority": "10",
                        "apns-push-type": "alert",
                    },
                    payload=payload_object
                )
            )

            # --- STEP 4: SEND ---
            try:
                # Note: Do not try to print(message) directly here to avoid serialization errors
                response = messaging.send(message, app=app_safexs)
                print(f"✅ Notification sent to {user['email']}: {response}")
                users_notified_count += 1
            except Exception as send_error:
                print(f"❌ Failed to send to {user['email']}: {str(send_error)}")

        return target_ble_id

    except SQLAlchemyError as e:
        raise RuntimeError(f"Database error: {str(e)}")
    except Exception as e:
        raise Exception(f"Exception error: {str(e)}")

# Sends a silent data-only message to an Android device to STOP the openDoor method
def stop_safexs_doorbell_ring(db: Session, bell_id: int, accepted_by_email: str = ""):
    """
    Call this function when a user Answers or Opens the door.
    It sends a STOP command to everyone else to silence their phones.
    """
    if app_safexs is None:   # SafeXS Firebase not configured (peers-only deployment)
        return None
    query = text("""
SELECT u.fcm_token, u.email
FROM peripheral_bell_user pbu
JOIN user u ON u.uuid = pbu.user_id
WHERE pbu.bell_id = :bell_id
AND pbu.is_active = 1
     """)

    try:
        users = db.execute(query, {"bell_id": bell_id}).mappings().fetchall()

        for user in users:
            # Don't send the STOP command to the person who actually answered!
            if user['email'] == accepted_by_email:
                continue

            fcm_token = user["fcm_token"]
            if fcm_token:
                message = messaging.Message(
                    data={
                        "action": "STOP_DOORBELL",  # Matches your Android logic
                    },
                    token=fcm_token,
                    android=messaging.AndroidConfig(priority="high", ttl=0),
                    apns=messaging.APNSConfig(
                        headers={"apns-priority": "5", "apns-push-type": "background"},
                        payload=messaging.APNSPayload(aps=messaging.Aps(content_available=True))
                    )
                )
                try:
                    messaging.send(message, app=app_safexs)
                    print(f"Sent STOP signal to {user['email']}")
                except Exception as e:
                    print(f"Failed to stop ring for {user['email']}: {e}")

    except Exception as e:
        print(f"Error in stop_safexs_doorbell_ring: {e}")