from base64 import b32encode, b64encode
import bcrypt
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from datetime import datetime, timedelta
import json
import jwt
#from constants import Constants

import pyotp
from robot.api.deco import keyword


# Verify password or token
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))

# Hash password or token
def hash_password(plain_password):
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(plain_password.encode('utf-8'), salt)
    return hashed_password

def create_access_token(data: dict, constants: dict):
    expires_delta = timedelta(minutes=constants["ACCESS_TOKEN_EXPIRE_MINUTES"])
    to_encode = data.copy()
    expire = datetime.now() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, constants["SECRET_KEY"], algorithm=constants["ALGORITHM"])
    token_type = "Bearer"
    return encoded_jwt, token_type, expire

def oauth_decrypt(token: str, constants: dict):
    return jwt.decode(token, constants["SECRET_KEY"], algorithms=[constants["ALGORITHM"]])

def encrypt(crypt_obj, message):
    # signature = self.private_key.sign(bytes(message, encoding='utf-8'), encoding='base64').decode("utf-8")
    signature = crypt_obj.private_key.sign(bytes(message, encoding="utf-8"))
    signature_base64 = b64encode(signature).decode("utf-8")
    payload = b64encode(crypt_obj.aes_cipher.encrypt(pad(bytes(message, encoding='utf-8'), AES.block_size))).decode("utf-8")

    collection = {
        "payload": payload,
        "signature": signature_base64
        # "signature": signature
    }
    return remove_space(add_semicolon(json.dumps(collection)))

@keyword('Get Online Unlock with ${timestamp} and ${topt_secret} as user ${user_id} and open lock for ${sig_duration} ms')
def get_online_unlock(crypt_obj, timestamp, user_id, sig_duration=1000):
    # crypt_obj.totp is a string
    totp_secret = b32encode(crypt_obj.totp_secret.encode('utf-8')).decode('utf-8')
    totp = pyotp.TOTP(totp_secret).now()
    collection = {
        "type": "online",
        "server_time": timestamp,
        "timeOpenMs": int(sig_duration),
        "key": user_id,
        "TOTP": totp
        #"TOTP": pyotp.TOTP(b32encode(bytes(crypt_obj.totp, encoding='utf-8'))).now()
    }
    return remove_space(json.dumps(collection))

def remove_space(data):
    return data.replace(" ", "")

def add_semicolon(data):
    return data + ";"

@keyword('Get Offline Unlock between ${timeslot_start} and ${timeslot_end} with ${timestamp} as user ${user_id} with expiry ${expiry} and open lock for ${sig_duration} ms')
def get_offline_unlock_with_timeslot(timestamp, timeslot_start, timeslot_end, user_id, sig_duration=1000):
    collection = {
        "type": "offline",
        "server_time": timestamp,
        "timeOpenMs": sig_duration,
        "key": user_id,
        "expiry": timeslot_end,
        "start_times": [timeslot_start], # [0] => no check
        "end_times": [timeslot_end]
    }
    return remove_space(json.dumps(collection))


