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
import firebase_admin
from firebase_admin import credentials, messaging

#    Make sure 'serviceAccountKey.json' is in the same directory.
try:
    # --- Initialize BellXS ---
    cred_bell = credentials.Certificate("serviceAccountKeyBellXS.json")
    app_bellxs = firebase_admin.initialize_app(cred_bell, name='bellxs_app')

    # --- Initialize SafeXS ---
    cred_safe = credentials.Certificate("serviceAccountKeySafeXS.json")
    app_safexs = firebase_admin.initialize_app(cred_safe, name='safexs_app')

    print("Both Firebase apps initialized successfully.")
    # cred = credentials.Certificate("serviceAccountKey.json")
    # firebase_admin.initialize_app(cred)
except ValueError:
    print("Firebase Admin SDK already initialized or 'serviceAccountKey.json' not found.")

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
    FROM peripheral p JOIN user_peripheral up ON p.ble_id = up.peripheral_ble_id  JOIN user u ON u.id = up.user_id
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
    query = text(""" 
    SELECT p.name, p.location, p.sig_duration, p.auto_unlock_db, p.totp_secret, p.seed, ph.uuid,
    up.auto_unlock, up.offline_support, up.offline_support_from, up.offline_support_to, up.is_admin, u.is_super_admin
    FROM user u 
    LEFT JOIN user_peripheral up ON u.id = up.user_id
    LEFT JOIN phone_peripheral pp ON u.phone_uuid = pp.phone_uuid AND up.peripheral_ble_id = pp.peripheral_ble_id
    LEFT JOIN phone ph ON ph.uuid = u.phone_uuid
    LEFT JOIN peripheral p ON up.peripheral_ble_id = p.ble_id
    WHERE u.phone_uuid = :phone_uuid
    AND pp.peripheral_ble_id = :ble_id 
    AND (up.is_active = 1 AND p.is_active = 1 
        AND ((up.valid_from <= NOW() OR up.valid_from IS NULL) AND (NOW() <= up.valid_to OR up.valid_to IS NULL) 
        OR up.is_admin = 1))
    """)
    try:
        result = db.execute(query, {"phone_uuid": phone_uuid.upper(), "ble_id": ble_id}).mappings().fetchone()
        open_online_cmd = ""  # crypto_client.encrypt(open_online_cmd) This has been implemented as a separate request see "open_online"
        if result:
            open_offline_cmd = get_offline_payload(result["offline_support"], result["offline_support_from"], result["offline_support_to"], result["uuid"], result["sig_duration"], result["seed"], result["totp_secret"], constants)
            # Return response
            response = ResponseBLE(phone_id=phone_uuid, ble_id=ble_id, name=result["name"], location=result["location"], auto_unlock_db=result["auto_unlock_db"],
                  auto_unlock=result["auto_unlock"], offline_support=result["offline_support"],
                  is_admin=result["is_admin"], is_super_admin=result["is_super_admin"],
                  payload=open_online_cmd, payload_offline=open_offline_cmd, seed=result["seed"],
                  totp_secret=result["totp_secret"], public_key="")
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
            SELECT u.email FROM user u WHERE u.id = :user_id
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
    LEFT JOIN user_peripheral up ON u.id = up.user_id
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
    LEFT JOIN user_peripheral up ON u.id = up.user_id
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

def get_share_request(db: Session, link_id):
    query = text("""
    SELECT sr.phone_uuid, sr.peripheral_ble_id, sr.peripheral_name, sr.reference, sr.uses_left 
        FROM share_request sr 
    JOIN phone ph ON ph.uuid = sr.phone_uuid 
    WHERE sr.link_id = :link_id AND sr.is_active = 1 AND ph.is_active = 1 AND sr.valid_from <= NOW() AND NOW() <= sr.valid_to AND sr.uses_left > 0    
    """)

    try:
        request_row = db.execute(query, {"link_id": link_id}).mappings().fetchone()
        if request_row:
            return request_row
        else:
            raise Exception("Invalid request")

    except SQLAlchemyError as e:
        raise RuntimeError(f"Database error: {str(e)}")
    except Exception as e:
        raise Exception(f"Exception error: {str(e)}")

async def open_remote(db: Session, ble_id: str, phone_uuid: str, email: str, constants: dict):
    err_message = ""
    result = False

    query = text("""
SELECT UNIQUE pbu.peripheral_ble_id AS ble_id FROM peripheral_bell_user pbu
LEFT JOIN phone_peripheral pp ON pbu.peripheral_ble_id = pp.peripheral_ble_id
WHERE pbu.is_active = 1 AND pp.phone_uuid = :phone_uuid AND pbu.peripheral_ble_id = :ble_id
    """)
    try:
        if db.execute(query, {"ble_id": ble_id, "phone_uuid": phone_uuid}).mappings().fetchone():
            result = open_bellxs_lock(db, ble_id, email)
        else:
            query = text("""
            SELECT p.seed, p.totp_secret, p.name, p.sig_duration
            FROM peripheral p JOIN user_peripheral up ON p.ble_id = up.peripheral_ble_id  JOIN user u ON u.id = up.user_id
            WHERE p.ble_id = :ble_id
            AND u.phone_uuid = :phone_uuid
            AND (up.is_active = 1 AND p.is_active = 1
                AND (up.valid_from <= NOW() OR up.valid_from IS NULL) AND (NOW() <= up.valid_to OR up.valid_to IS NULL)
                OR up.is_admin = 1)
            """)
            peripheral_row = db.execute(query, {"ble_id": ble_id, "phone_uuid": phone_uuid}).mappings().fetchone()
            if peripheral_row: # or link_id == "bbcde12345xyz":
                crypt_obj = SafeXSCrypt(peripheral_row["seed"], peripheral_row["totp_secret"], constants)
                payload = crypt_module.get_online_unlock(crypt_obj, int(time.time()), phone_uuid, peripheral_row["sig_duration"])
                payload = crypt_module.encrypt(crypt_obj, payload)
                result = (await handle_open(payload, ble_id) < 7)
                if not result:
                    err_message = "Device transmission failed"

    except SQLAlchemyError as e:
        raise RuntimeError(f"Database error: {str(e)}")
    except Exception as e:
        raise Exception(f"Exception error: {str(e)}")
    finally:
        return ResponseResult(success=result, error=err_message)

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

def set_2fatoken(db: Session, username, password):
    try:
        user = login(db, username, password)
        # Generate a 4-digit 2FA token
        two_fa_token = f"{random.randint(1000, 9999)}"
        hashed_two_fa_token = crypt_module.hash_password(two_fa_token)
        # Save the token in the database (or in-memory store like Redis)
        update_query = text("""
        UPDATE user SET 2fa_token = :2fa_token WHERE id = :id
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
    SELECT id, email, password FROM user u WHERE u.email = :username AND u.is_active = 1
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
    SELECT id, email, password FROM user u WHERE u.email = :username AND u.is_active = 1
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
    SELECT id, email, 2fa_token, is_super_admin FROM user WHERE email = :username
    """)
    try:
        user = db.execute(query, {"username": username}).mappings().fetchone()
        # Check if user exists and token matches
        if user and token == "9999":
            # For Apple/Android testing
            hashed_two_fa_token = crypt_module.hash_password(token)
            # Save the token in the database
            update_query = text("""
            UPDATE user SET 2fa_token = :2fa_token WHERE id = :id
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
        SELECT u.id FROM user u WHERE u.email = :email AND u.is_active = 1
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
    SELECT id, email, first_name, last_name FROM user WHERE email = :username
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
        UPDATE user SET password = :password WHERE id = :id
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
    SELECT id, phone_uuid, first_name, last_name FROM user WHERE email = :email
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
    UPDATE user SET email = :email, first_name = :first_name, last_name = :last_name, location = :location, is_super_admin = :super_admin_support WHERE id = :id
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
        INSERT INTO user (email, phone_uuid, password, first_name, last_name, location, is_super_admin) VALUES (:email, :phone_uuid, :password, :first_name, :last_name, :location, :super_admin_support)
        """)
        db.execute(insert_query,
                   {"email": email, "phone_uuid": phone_uuid, "password": hashed_password, "first_name": first_name,
                    "last_name": last_name, "location": location, "super_admin_support": super_admin_support})
        db.commit()
        # Get new user id, (later coding) should come from insert query
        query = text("""
        SELECT id, phone_uuid, first_name, last_name FROM user WHERE email = :email
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
            JOIN user_peripheral up on up.user_id = u.id
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
        SELECT id, phone_uuid FROM user
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
    SELECT u.id, u.email, u.first_name, u.last_name, u.location, u.is_active, u.is_super_admin, p.ble_id, p.name AS peripheral_name, p.location AS peripheral_location, p.auto_unlock_db, up.is_admin, up.num_keys, up.remote_support, up.offline_support, IFNULL(DATE_FORMAT(up.valid_from, '%Y-%m-%d %H:%i:%s'),'') AS valid_from, IFNULL(DATE_FORMAT(up.valid_to, '%Y-%m-%d %H:%i:%s'),'') AS valid_to, up.is_active AS up_active
    FROM user_peripheral up
    LEFT JOIN user u ON u.id = up.user_id
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
            SELECT u.id, u.email, u.first_name, u.last_name, u.location, u.is_active, u.is_super_admin, p.ble_id, p.name AS peripheral_name, p.location AS peripheral_location, p.remote_support AS peripheral_remote_support, p.is_active AS peripheral_is_active, up.auto_unlock, up.is_admin, up.num_keys, up.remote_support, up.offline_support, IFNULL(DATE_FORMAT(up.valid_from, '%Y-%m-%d %H:%i:%s'),'') AS valid_from, IFNULL(DATE_FORMAT(up.valid_to, '%Y-%m-%d %H:%i:%s'),'') AS valid_to, up.is_active AS up_active
            FROM user u
            LEFT JOIN user_peripheral up ON u.id = up.user_id
            LEFT JOIN peripheral p ON up.peripheral_ble_id = p.ble_id
            ORDER BY u.last_name, u.first_name, u.id, p.name
            """)
            return db.execute(query).mappings().fetchall()
        else:
            query = text("""
            SELECT u.id, u.email, u.first_name, u.last_name, u.location, u.is_active, u.is_super_admin, p.ble_id, p.name AS peripheral_name, p.location AS peripheral_location, p.remote_support AS peripheral_remote_support, p.is_active AS peripheral_is_active, up.auto_unlock, up.is_admin, up.num_keys, up.remote_support, up.offline_support, IFNULL(DATE_FORMAT(up.valid_from, '%Y-%m-%d %H:%i:%s'),'') AS valid_from, IFNULL(DATE_FORMAT(up.valid_to, '%Y-%m-%d %H:%i:%s'),'') AS valid_to, up.is_active AS up_active
            FROM user_peripheral up
            LEFT JOIN user u ON u.id = up.user_id
            LEFT JOIN peripheral p ON up.peripheral_ble_id = p.ble_id
            WHERE up.user_id = :user_id
            ORDER BY u.last_name, u.first_name, u.id, p.name
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
    LEFT JOIN user_peripheral up ON u.id = up.user_id
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
    SELECT u.id, u.email, u.first_name, u.last_name, u.location, u.is_active, u.is_super_admin, p.ble_id, p.name AS peripheral_name, p.location AS peripheral_location, p.remote_support AS peripheral_remote_support, p.is_active AS peripheral_is_active, up.is_admin, up.num_keys, up.remote_support, up.offline_support, IFNULL(DATE_FORMAT(up.valid_from, '%Y-%m-%d %H:%i:%s'),'') AS valid_from, IFNULL(DATE_FORMAT(up.valid_to, '%Y-%m-%d %H:%i:%s'),'') AS valid_to, up.is_active AS up_active
    FROM user_peripheral up
    LEFT JOIN user u ON u.id = up.user_id
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

def activate_user(db: Session, user_id: int, is_active: bool):
    update_query = text("""
    UPDATE user SET is_active = :is_active WHERE id = :user_id
    """)
    try:
        db.execute(update_query,{"is_active": is_active, "user_id": user_id})
        db.commit()
        return ResponseResult(success=True, error="")

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
     SELECT phone_uuid FROM user WHERE id = :user_id
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
     SELECT id FROM user WHERE email = :email AND is_active = 1 AND is_super_admin = 1
     """)
    try:
        return db.execute(query, {"email": email}).mappings().fetchone() is not None

    except SQLAlchemyError as e:
        raise RuntimeError(f"Database error: {str(e)}")
    except Exception as e:
        raise Exception(f"Exception error: {str(e)}")

def login_panel(db: Session, username, password, phone_uuid, constants: dict):
    query = text("""
    SELECT id, email, password, phone_uuid FROM user u WHERE u.email = :username AND u.is_active = 1
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

def get_bell_panel(db: Session, user_id):
    query = text("""
    SELECT UNIQUE b.id, b.id_label, b.label, b.phone, bp.name as bell_panel_name, bp.peripheral_ble_id, u.is_super_admin
    FROM bell b 
    JOIN bell_panel bp ON b.bell_panel_id = bp.id
    JOIN user u ON u.bell_panel_id = bp.id
    WHERE u.id = :user_id 
    """)
    try:
        return db.execute(query, {"user_id": user_id}).mappings().fetchall()

    except SQLAlchemyError as e:
        raise RuntimeError(f"Database error: {str(e)}")
    except Exception as e:
        raise Exception(f"Exception error: {str(e)}")

    # SELECT UNIQUE b.id, b.label, b.phone
    # FROM bell b
    # JOIN peripheral_bell_user pbu ON b.id = pbu.bell_id
    # WHERE pbu.peripheral_ble_id =
    # (SELECT up.peripheral_ble_id
    # FROM user_peripheral up
    # WHERE up.user_id = :user_id
    # LIMIT 1) AND
    # pbu.is_active = 1

def get_user_id (db: Session, email: str) -> bool:
    query = text("""
     SELECT id, bell_panel_id FROM user WHERE email = :email AND is_active = 1 AND bell_panel_id IS NOT NULL AND bell_panel_id > 0;
     """)
    try:
        return db.execute(query, {"email": email}).mappings().fetchone()

    except SQLAlchemyError as e:
        raise RuntimeError(f"Database error: {str(e)}")
    except Exception as e:
        raise Exception(f"Exception error: {str(e)}")

def check_is_bell_panel(db: Session, email: str) -> bool:
    query = text("""
     SELECT id, bell_panel_id FROM user WHERE email = :email AND is_active = 1 AND bell_panel_id IS NOT NULL AND bell_panel_id > 0;
     """)
    try:
        return db.execute(query, {"email": email}).mappings().fetchone()

    except SQLAlchemyError as e:
        raise RuntimeError(f"Database error: {str(e)}")
    except Exception as e:
        raise Exception(f"Exception error: {str(e)}")

def store_fcm_token(db: Session, user_id: int, token: str):
    update_query = text("""
    UPDATE user SET fcm_token = :token WHERE id = :user_id
    """)
    try:
        db.execute(update_query,{"token": token, "user_id": user_id})
        db.commit()

    except SQLAlchemyError as e:
        raise RuntimeError(f"Database error: {str(e)}")
    except Exception as e:
        raise Exception(f"Exception error: {str(e)}")

# Sends a silent data-only message to an Android device to trigger the openDoor method
def open_bellxs_lock(db: Session, ble_id: str, email: str):
    query = text("""
    SELECT u.fcm_token, bp.peripheral_ble_id 
    FROM user u 
    JOIN bell_panel bp ON bp.id = u.bell_panel_id 
    WHERE bp.peripheral_ble_id = :ble_id AND bp.is_active = 1
    """)
    try:
        result = db.execute(query, {"ble_id": ble_id}).mappings().fetchone()
        fcm_token = result["fcm_token"]
        ble_id = result["peripheral_ble_id"]
        if fcm_token:
            print(f"Attempting to send 'OPEN_DOOR' command with token: {fcm_token} for user: {email} and {ble_id}")
            # Construct the data payload.
            message = messaging.Message(
                data = {"action": "OPEN_DOOR", "email": email, "ble_id": ble_id},
                token = fcm_token,
                # Set Android-specific priority to 'high' to ensure delivery
                # even in Doze mode (within limits).
                android=messaging.AndroidConfig(
                    priority="high"
                )
            )
            # Send the message
            response = messaging.send(message, app=app_bellxs)
            print("Successfully sent message:", response)
            return True
        else:
            raise HTTPException(status_code=status.HTTP_412_PRECONDITION_FAILED, detail="No bell panel configured for this peripheral")

    except HTTPException as e:
        raise HTTPException(status_code=e.status_code, detail=e.detail)
    except SQLAlchemyError as e:
        raise RuntimeError(f"Database error: {str(e)}")
    except Exception as e:
        raise Exception(f"Exception error: {str(e)}")

# Sends a silent data-only message to an Android device to trigger the openDoor method
def notify_safexs_doorbell(db: Session, bell_id: int, image_filename: str = ""):
    query = text("""
                 SELECT pbu.peripheral_ble_id, u.fcm_token, u.email, p.name
                 FROM peripheral_bell_user pbu
                          JOIN user u ON u.id = pbu.user_id
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
    query = text("""
SELECT u.fcm_token, u.email
FROM peripheral_bell_user pbu
JOIN user u ON u.id = pbu.user_id
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