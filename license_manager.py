import logging
from sqlalchemy.orm import Session
from sqlalchemy import text

import os
import json
import base64
import hmac
import hashlib
import random
import time
import datetime
from cryptography.fernet import Fernet
import httpx

class LicenseManager:
    def __init__(
        self,
        enc_path="constants.json.enc",
        init_license_server_url="https://api.safexs.eu:7999/v1/get_license/",
        init_secret_api="162e8d933b21b4697dd44090ab057",
        init_uuid="184e4933-d320-4d12-8f27-c2478dcd7783",
        init_shared_key=b'UeB8vW5gUgjBrL1jOlFhoLnkEZTMVD9moU_4q2Zow55=',
        usage_users=-1,
        usage_keys=-1,
        usage_peripherals=-1,
    ):
        self.enc_path = enc_path
        self.init_license_server_url = init_license_server_url
        self.init_secret_api = init_secret_api
        self.init_uuid = init_uuid
        self.init_shared_key = init_shared_key
        self.usage_users = usage_users
        self.usage_keys = usage_keys
        self.usage_peripherals = usage_peripherals
        self.constants = None
        self.license_server_secret_master = None
        #self._just_registered = False
        self.db: Session = None
        self.last_renewal_date = None  # Track last renewal (YYYY-MM-DD string)

    def get_today_str(self):
        return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")

    def derive_fernet_key(self, shared_key: bytes, date_str: str) -> bytes:
        digest = hmac.new(shared_key, date_str.encode(), hashlib.sha256).digest()
        return base64.urlsafe_b64encode(digest[:32])

    def api_post(self, url, api_key, payload):
        headers = {
            "accept": "application/octet-stream",
            "Content-Type": "application/json",
            "X-API-Key": api_key
        }
        with httpx.Client(verify=False) as client: # MARC: remove verify=False for production
            resp = client.post(url, headers=headers, json=payload)
            resp.raise_for_status()
            return resp.content

    def decrypt_constants(self, enc_file_path, fernet_key):
        with open(enc_file_path, "rb") as infile:
            encrypted = infile.read()
        fernet = Fernet(fernet_key)
        decrypted = fernet.decrypt(encrypted)
        return json.loads(decrypted)

    def initial_registration(self):
        today_str = self.get_today_str()
        fernet_key = self.derive_fernet_key(self.init_shared_key, today_str)
        payload = {
            "uuid": self.init_uuid,
            "usage_users": self.usage_users,
            "usage_keys": self.usage_keys,
            "usage_peripherals": self.usage_peripherals,
        }
        response = self.api_post(self.init_license_server_url, self.init_secret_api, payload)
        with open(self.enc_path, "wb") as outfile:
            outfile.write(response)
        constants = self.decrypt_constants(self.enc_path, fernet_key)
        self.constants = constants
        self.license_server_secret_master = constants["LICENSE_SERVER_SECRET_MASTER"]
        # self._just_registered = True

    def load_constants(self):
        # Try today's and yesterday's date in case of clock skew
        with open(self.enc_path, "rb") as infile:
            encrypted = infile.read()
        for date_str in [
            self.get_today_str(),(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)).strftime("%Y-%m-%d")
        ]:
            try:
                if self.license_server_secret_master:
                    fernet_key = self.derive_fernet_key(self.license_server_secret_master.encode(), date_str)
                else:
                    fernet_key = self.derive_fernet_key(self.init_shared_key, date_str)
                fernet = Fernet(fernet_key)
                decrypted = fernet.decrypt(encrypted)
                constants = json.loads(decrypted)
                self.constants = constants
                self.license_server_secret_master = constants["LICENSE_SERVER_SECRET_MASTER"]
                return
            except Exception:
                continue
        raise RuntimeError("Failed to decrypt constants.json.enc with any known key/date.")

    def ensure_constants(self):
        if not os.path.exists(self.enc_path):
            try:
                self.initial_registration()
            except Exception as e:
                print("Encryption problem:", self.filter_exception_message(e))
                print("Re-running initial registration...")
                self.initial_registration()

        else:
            try:
                # if self._just_registered:
                #     # Just registered; skip load_constants ONCE and clear the flag.
                #     self._just_registered = False
                #     return
                self.load_constants()
            except Exception as e:
                print("Loading problem:", "trying again ...") #str(e)
                print("Re-running initial registration...")
                os.remove(self.enc_path)
                try:
                    self.initial_registration()
                except Exception as e:
                    print("Encryption problem:", self.filter_exception_message(e))
                    print("Final re-running initial registration...")
                    self.initial_registration()
            self.renew_license()  # Invalidates share secret (init_shared_key)

    def filter_exception_message(self, e: Exception):
        msg:str = str(e)
        return  msg[:msg.find(" for url")] if " for url" in msg else msg

    def wait_for_renew(self, hour_start=3, hour_end=4):
        # Waits for a random moment between hour_start and hour_end (UTC+1) before proceeding.
        # Example: wait_for_renew(3, 4) waits between 03:00 and 04:00 UTC+1.
        utc2_now = datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=2)))
        # Calculate seconds since
        window_seconds = (hour_end - hour_start) * 3600
        random_seconds = random.randint(0, window_seconds - 1)
        target_time = utc2_now.replace(hour=hour_start, minute=0, second=0, microsecond=0) + datetime.timedelta(
            seconds=random_seconds)
        wait_seconds = (target_time - utc2_now).total_seconds()
        if wait_seconds > 0:
            print(f"[LicenseManager] Waiting {int(wait_seconds)} seconds to execute license renewal (UTC+2) between {hour_start:02d}:00-{hour_end:02d}:00...")
            time.sleep(wait_seconds)
        else:
            print("[LicenseManager] Window has already passed for today; renewing immediately.")

    def renew_license(self):
        # Renews the license immediately using the current constants.
        if self.db:
            self.get_license_usage() # update usage data
        today_str = self.get_today_str()
        shared_key = self.license_server_secret_master.encode()
        fernet_key = self.derive_fernet_key(shared_key, today_str)
        fernet = Fernet(fernet_key)
        payload = {
            "uuid": self.constants["SERVER_UUID"],
            "usage_users": self.usage_users,
            "usage_keys": self.usage_keys,
            "usage_peripherals": self.usage_peripherals,
        }
        api_key = self.constants["LICENSE_SERVER_SECRET_API"]
        url = self.constants["LICENSE_SERVER_URL"]
        response = self.api_post(url, api_key, payload)
        with open(self.enc_path, "wb") as outfile:
            outfile.write(response)
        # Update the in-memory constants after renewal
        constants = json.loads(fernet.decrypt(response))
        self.constants = constants
        self.license_server_secret_master = constants["LICENSE_SERVER_SECRET_MASTER"]
        print("[LicenseManager] License renewed successfully.")
        self.last_renewal_date = datetime.date.today().isoformat()

    def daily_renewal_loop(self, hour_start=3, hour_end=4):
        while True:
            try:
                today = datetime.date.today().isoformat()
                if self.last_renewal_date == today:
                    # Already renewed today: sleep until tomorrow's window
                    utc2_now = datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=2)))
                    tomorrow = utc2_now + datetime.timedelta(days=1)
                    next_window = tomorrow.replace(hour=hour_start, minute=0, second=0, microsecond=0)
                    sleep_seconds = (next_window - utc2_now).total_seconds()
                    print(f"Already renewed today. Sleeping {int(sleep_seconds)} seconds until next window...")
                    time.sleep(sleep_seconds)
                else:
                    # Not yet renewed today: do it
                    self.wait_for_renew(hour_start, hour_end)
                    self.renew_license()
            except Exception as e:
                print("[LicenseManager] Renewal loop error:", str(e))
                time.sleep(600)  # Wait 10 minutes before trying again

    def get_constants(self):
        return self.constants

    def get_license_usage(self):
        #self.db.expire_all()
        self.db.rollback()
        # Fetch number active users
        query = text("""
        SELECT COUNT(id) AS count FROM user WHERE is_active = 1
        """)
        try:
            self.usage_users = self.db.execute(query).mappings().fetchone()["count"]
            # Fetch number active keys
            query = text("""
            SELECT SUM(num_keys) AS sum FROM user_peripheral WHERE is_active = 1
            """)
            row = self.db.execute(query).mappings().fetchone()
            self.usage_keys = int(row["sum"] or 0)
            # Fetch number active peripherals
            query = text("""
            SELECT COUNT(ble_id) AS count FROM peripheral WHERE is_active = 1
            """)
            self.usage_peripherals = self.db.execute(query).mappings().fetchone()["count"]

        except Exception as e:
            logging.error(f"Get license usage failecd: {e}")
