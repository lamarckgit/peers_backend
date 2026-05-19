
import httpx
import datetime
import hmac
import hashlib
import base64
import json
from cryptography.fernet import Fernet

def get_today_str():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")

def derive_fernet_key(shared_key: bytes, date_str: str) -> bytes:
    digest = hmac.new(shared_key, date_str.encode(), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest[:32])

def reproduce():
    url = "https://192.168.68.114:7999/v1/get_license/"
    api_key = "162e8d933b21b4697dd44090ab057"
    uuid = "184e4933-d320-4d12-8f27-c2478dcd7783"
    shared_key = b'UeB8vW5gUgjBrL1jOlFhoLnkEZTMVD9moU_4q2Zow55='
    
    payload = {
        "uuid": uuid,
        "usage_users": -1,
        "usage_keys": -1,
        "usage_peripherals": -1,
    }
    
    headers = {
        "accept": "application/octet-stream",
        "Content-Type": "application/json",
        "X-API-Key": api_key
    }
    
    print(f"Requesting URL: {url}")
    print(f"Headers: {headers}")
    print(f"Payload: {payload}")
    
    try:
        with httpx.Client() as client:
            resp = client.post(url, headers=headers, json=payload)
            print(f"Response status: {resp.status_code}")
            resp.raise_for_status()
            print("Successfully received response!")
            
            # Try to decrypt if we got a response
            today_str = get_today_str()
            fernet_key = derive_fernet_key(shared_key, today_str)
            fernet = Fernet(fernet_key)
            decrypted = fernet.decrypt(resp.content)
            constants = json.loads(decrypted)
            print("Successfully decrypted constants!")
            print(constants)
            
    except httpx.HTTPStatusError as e:
        print(f"HTTP Error: {e}")
        if e.response.status_code == 403:
            print("Confirmed 403 Forbidden.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    reproduce()
