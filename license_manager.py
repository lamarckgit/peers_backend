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

from classes.api_manager import ApiManager

class LicenseManager:
    def __init__(
        self,
        enc_path="constants.json.enc",
        init_license_server_url="https://api.safexs.eu/license/v1/get_license/",
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
        self.last_renewal_error = None  # str of last renewal failure, or None if healthy (surfaced via /health)
        self.last_renewal_path = os.path.join(os.path.dirname(self.enc_path), "last_renewal.enc")
        # Persisted copy of the master secret, encrypted with the (constant)
        # bootstrap key so a cold start can recover it BEFORE constants.json.enc
        # is decrypted — that file may be master-encrypted after a renewal.
        self.master_path = os.path.join(os.path.dirname(self.enc_path), "master.enc")
        # Verify the license server's TLS cert by default; allow opt-out only for
        # local/dev via LICENSE_SERVER_VERIFY_TLS=false (never set in production).
        verify_tls = os.environ.get("LICENSE_SERVER_VERIFY_TLS", "true").lower() not in ("false", "0", "no")
        self.api = ApiManager(verify_tls=verify_tls)

    def _renewal_fernet_key(self):
        # Encrypts last_renewal.enc with the current master secret so a local
        # attacker can't extend the renewal date by editing a plain-text file.
        if not self.license_server_secret_master:
            return None
        return self.derive_fernet_key(
            self.license_server_secret_master.encode(),
            "last_renewal_date",
        )

    def _load_last_renewal_date(self):
        key = self._renewal_fernet_key()
        if key is None:
            self.last_renewal_date = None
            return
        try:
            with open(self.last_renewal_path, "rb") as f:
                encrypted = f.read()
            value = Fernet(key).decrypt(encrypted).decode().strip()
            datetime.date.fromisoformat(value)
            self.last_renewal_date = value
        except Exception:
            self.last_renewal_date = None

    def _save_last_renewal_date(self):
        if self.last_renewal_date is None:
            return
        key = self._renewal_fernet_key()
        if key is None:
            return
        try:
            encrypted = Fernet(key).encrypt(self.last_renewal_date.encode())
            tmp_path = self.last_renewal_path + ".tmp"
            with open(tmp_path, "wb") as f:
                f.write(encrypted)
            os.replace(tmp_path, self.last_renewal_path)
        except OSError as e:
            logging.error(f"Failed to persist last_renewal_date: {e}")

    def _master_fernet_key(self):
        # Date-independent key derived from the constant bootstrap secret, used
        # only to persist the master secret locally. It must NOT depend on the
        # master (which would be circular) nor on the date (it has to be
        # readable on any later day at cold start).
        return self.derive_fernet_key(self.init_shared_key, "license_server_secret_master")

    def _load_master_secret(self):
        # Recover a previously persisted master secret so load_constants() can
        # decrypt a renewed (master-encrypted) constants.json.enc at cold start.
        try:
            with open(self.master_path, "rb") as f:
                encrypted = f.read()
            self.license_server_secret_master = Fernet(self._master_fernet_key()).decrypt(encrypted).decode().strip()
        except Exception:
            # No persisted master yet (first run, or pre-fix deployment) —
            # load_constants() falls back to the bootstrap key.
            pass

    def _save_master_secret(self):
        if not self.license_server_secret_master:
            return
        try:
            encrypted = Fernet(self._master_fernet_key()).encrypt(self.license_server_secret_master.encode())
            tmp_path = self.master_path + ".tmp"
            with open(tmp_path, "wb") as f:
                f.write(encrypted)
            os.replace(tmp_path, self.master_path)
        except OSError as e:
            logging.error(f"Failed to persist master secret: {e}")

    def get_today_str(self):
        return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")

    def derive_fernet_key(self, shared_key: bytes, date_str: str) -> bytes:
        digest = hmac.new(shared_key, date_str.encode(), hashlib.sha256).digest()
        return base64.urlsafe_b64encode(digest[:32])

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
        response = self.api.api_post(self.init_license_server_url, payload, self.init_secret_api)
        with open(self.enc_path, "wb") as outfile:
            outfile.write(response)
        constants = self.decrypt_constants(self.enc_path, fernet_key)
        self.constants = constants
        self.license_server_secret_master = constants["LICENSE_SERVER_SECRET_MASTER"]
        self._save_master_secret()
        # self.last_renewal_date = datetime.date.today().isoformat()
        # self._just_registered = True

    def load_constants(self):
        # The on-disk file may be encrypted with either the bootstrap key (after
        # an initial registration) or the master key (after a daily renewal), so
        # try both. Try today's and yesterday's date in case of clock skew.
        with open(self.enc_path, "rb") as infile:
            encrypted = infile.read()
        candidate_secrets = [self.init_shared_key]
        if self.license_server_secret_master:
            # Recovered from master.enc (see _load_master_secret); lets us read a
            # renewed, master-encrypted file at cold start instead of forcing a
            # destructive re-registration.
            candidate_secrets.append(self.license_server_secret_master.encode())
        dates = [
            self.get_today_str(),
            (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)).strftime("%Y-%m-%d"),
        ]
        for date_str in dates:
            for secret in candidate_secrets:
                try:
                    fernet_key = self.derive_fernet_key(secret, date_str)
                    decrypted = Fernet(fernet_key).decrypt(encrypted)
                    constants = json.loads(decrypted)
                    self.constants = constants
                    self.license_server_secret_master = constants["LICENSE_SERVER_SECRET_MASTER"]
                    self._save_master_secret()
                    return
                except Exception as e:
                    print("[LicenseManager] Decrypt error:", str(e))
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
            # Recover any persisted master secret first so load_constants() can
            # decrypt a renewed (master-encrypted) file without re-registering.
            self._load_master_secret()
            try:
                # if self._just_registered:
                #     # Just registered; skip load_constants ONCE and clear the flag.
                #     self._just_registered = False
                #     return
                self.load_constants()
            except Exception as e:
                print("Loading problem:", "trying again ...") #str(e)
                print("Re-running initial registration...")
                # NOTE: do NOT os.remove(self.enc_path) here. initial_registration()
                # overwrites the file on success, and keeping the old file means a
                # failed re-registration doesn't leave us with no constants at all.
                try:
                    self.initial_registration()
                except Exception as e:
                    print("Encryption problem:", self.filter_exception_message(e))
                    print("Final re-running initial registration...")
                    self.initial_registration()
            # NOTE: do NOT call self.daily_renewal_loop() here — it's an
            # infinite while-True and would block main.py from starting uvicorn.
            # The lifespan thread in main.py owns the loop.
            # self.daily_renewal_loop()

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

    def renew_license(self, action_id: int = -1):
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
            "action_id": action_id,
        }
        api_key = self.constants["LICENSE_SERVER_SECRET_API"]
        url = self.constants["LICENSE_SERVER_URL"]
        response = self.api.api_post(url, payload, api_key)
        # The server returns the renewal master-encrypted; decrypt it in memory.
        constants = json.loads(fernet.decrypt(response))
        self.constants = constants
        self.license_server_secret_master = constants["LICENSE_SERVER_SECRET_MASTER"]
        # Persist re-encrypted with the bootstrap key (NOT the raw master-encrypted
        # response). A cold restart has no master secret in memory yet, so the
        # on-disk file must be decryptable by load_constants() with init_shared_key.
        boot_key = self.derive_fernet_key(self.init_shared_key, today_str)
        with open(self.enc_path, "wb") as outfile:
            outfile.write(Fernet(boot_key).encrypt(json.dumps(constants, ensure_ascii=False).encode("utf-8")))
        self._save_master_secret()
        logging.info("[LicenseManager] License renewed successfully.")
        self.last_renewal_date = datetime.date.today().isoformat()
        self.last_renewal_error = None  # clear any prior failure now that we've recovered
        self._save_last_renewal_date()

    def daily_renewal_loop(self, hour_start=3, hour_end=4):
        self._load_last_renewal_date()
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
                    if self.last_renewal_date is None:
                        # After initial registration, last_renewal_date is None.
                        self.last_renewal_date = datetime.date.today().isoformat()
                        self._save_last_renewal_date()
                    else:
                        # Not yet renewed today: do it
                        self.wait_for_renew(hour_start, hour_end)
                        self.renew_license()
            except Exception as e:
                # Record + log so a stuck renewal is visible via /health and the
                # rotating log, instead of failing silently until the license expires.
                self.last_renewal_error = str(e)
                logging.error(f"[LicenseManager] Renewal loop error: {e}")
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
