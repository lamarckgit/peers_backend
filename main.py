import base64
import logging
import os
import ssl
import threading
import time

import fastapi

from classes.database_class import Database
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
from pydantic import BaseModel
from sqlalchemy.orm import Session
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import HTMLResponse
from typing import Dict, List, Optional

# 1. Create global instances
license_manager = LicenseManager()
license_manager.ensure_constants()    # Make sure constants are loaded!
database = Database(license_manager.constants["DATABASE_URL"])
license_manager_thread = None
# Ensure the directory exists
SNAPSHOT_DIR = "static/snapshots"
os.makedirs(SNAPSHOT_DIR, exist_ok=True)

# 2. Background thread runner
def run_license_manager():
    license_manager.daily_renewal_loop()

# 3. Lifespan context
@asynccontextmanager
async def lifespan(app: FastAPI):
    global license_manager_thread
    if not license_manager_thread or not license_manager_thread.is_alive():
        license_manager_thread = threading.Thread(target=run_license_manager, daemon=True)
        license_manager_thread.start()
        logging.info("Started LicenseManager renewal thread.")
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

# Store active connections: bell_id -> WebSocket
class ConnectionManager:
    def __init__(self):
        # We store connections mapped by a unique ID (e.g., "bell_101", "safe_user_5")
        self.active_connections: Dict[str, WebSocket] = {}

    async def connect(self, client_id: str, websocket: WebSocket):
        await websocket.accept()
        self.active_connections[client_id] = websocket
        print(f"Client connected: {client_id}")

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
                # Forward the exact message to the target peer
                # We add the 'sender' ID so the target knows who replied
                data["sender"] = client_id
                await manager.send_personal_message(data, target_id)

    except WebSocketDisconnect:
        manager.disconnect(client_id)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
templates = Jinja2Templates(directory="templates")
ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ssl_context.load_cert_chain("fullchain.pem", keyfile="privkey.pem")
# Use FastAPI's APIKeyHeader dependency to fetch a secret key from headers
api_key_header = APIKeyHeader(name="x-api-key")

class RequestAddUser(BaseModel):
    uuid: str
    email: str
    full_name: str
    location: str
    super_admin_support: bool
    email_support: bool

class RequestActivateUser(BaseModel):
    uuid: str
    id: int
    is_active: bool

class RequestActivateUserLock(BaseModel):
    uuid: str
    id: int
    ble_id: str
    is_active: bool

class RequestId(BaseModel):
    uuid: str

class RequestUuIdId(BaseModel):
    uuid: str
    id: int

class RequestUuIdBleId(BaseModel):
    uuid: str
    ble_id: str

class RequestStoreFCMToken(BaseModel):
    uuid: str
    fcm_token: str

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

@app.post("/v1/activate_user/", response_model=response_module.ResponseResult, dependencies=[Depends(verify_api_key)])
async def activate_user(params: RequestActivateUser, username: response_module.ResponseUsername = Depends(check_credentials), db: Session = Depends(get_db)):
    try:
        if username: #if creditential valid => email
            if response_module.check_is_super_admin(db, username.email):
                response = response_module.activate_user(db, params.id, params.is_active)
                response_module.log_online_action(db, "", params.uuid, 13 if params.is_active else 14, True, "", params.id, "")
                return response

        raise Exception(f"Exception error: Unauthorized")

    except Exception as e:
        return JSONResponse(content={"success": False, "error": str(e)}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

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



@app.post("/v1/bellxs_image/", response_model=response_module.ResponseImage, dependencies=[Depends(verify_api_key)])
async def post_bellxs_image(params: RequestGetImage, username: response_module.ResponseUsername = Depends(check_credentials), db: Session = Depends(get_db)):
    """
    Retrieves the image file, converts it to Base64, and returns it in JSON.
    """
    # 1. Verify Authentication
    if not username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

    # 2. Security Check (Directory Traversal)
    filename = params.image_filename
    if ".." in filename or "/" in filename or "\\" in filename:
        return response_module.ResponseImage(success=False, image_data="", error="Invalid filename")

    # 3. Construct path
    file_path = os.path.join("static/snapshots", filename)

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

