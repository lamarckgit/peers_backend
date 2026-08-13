"""
Seed / update the App Store review demo contact's `user` row and public peer code.

Idempotent. Run ONCE per backend, from the repo root (so the license files resolve):

    python -m functions.seed_demo_bot            # create or update the demo contact
    python -m functions.seed_demo_bot --remove   # delete it and its friendships after review

It creates (or updates) a SINGLE `user` row whose uuid = demo_bot.DEMO_BOT_UUID, with the
fixed public code demo_bot.DEMO_BOT_CODE, so a reviewer can add it via Friends > Add Friend.
Nothing else in the database is touched. Optionally give the contact an avatar by dropping a
JPEG at  static/profile_images/peer_<DEMO_BOT_UUID>.jpg  (the app shows a placeholder otherwise).
"""

import sys

from sqlalchemy import text

from license_manager import LicenseManager
from classes.database_class import Database
from functions import demo_bot


def main():
    remove = "--remove" in sys.argv

    lm = LicenseManager()
    lm.ensure_constants()
    db = Database(lm.constants["DATABASE_URL"]).create_session()
    uuid_bytes = bytes.fromhex(demo_bot.DEMO_BOT_UUID)

    try:
        if remove:
            db.execute(text("DELETE FROM user_user WHERE uuid_1 = :u OR uuid_2 = :u"), {"u": uuid_bytes})
            db.execute(text("DELETE FROM user WHERE uuid = :u"), {"u": uuid_bytes})
            db.commit()
            print(f"Removed demo contact {demo_bot.DEMO_BOT_UUID} and any friendships it held.")
            return

        # Refuse to hijack a real peer's code — pick a different PEERS_DEMO_BOT_CODE instead.
        clash = db.execute(
            text("SELECT uuid FROM user WHERE peer_name = :c AND uuid <> :u"),
            {"c": demo_bot.DEMO_BOT_CODE, "u": uuid_bytes},
        ).fetchone()
        if clash:
            print(f"ABORT: peer code {demo_bot.DEMO_BOT_CODE!r} is already used by another peer "
                  f"({clash[0].hex()}). Set PEERS_DEMO_BOT_CODE to a free code and re-run.")
            sys.exit(1)

        exists = db.execute(text("SELECT 1 FROM user WHERE uuid = :u"), {"u": uuid_bytes}).fetchone()
        if exists:
            db.execute(
                text("UPDATE user SET name = :n, about_me = :a, peer_name = :c WHERE uuid = :u"),
                {"n": demo_bot.DEMO_BOT_NAME, "a": demo_bot.DEMO_BOT_ABOUT,
                 "c": demo_bot.DEMO_BOT_CODE, "u": uuid_bytes},
            )
            print("Updated existing demo contact.")
        else:
            db.execute(
                text("INSERT INTO user (uuid, name, about_me, peer_name) VALUES (:u, :n, :a, :c)"),
                {"u": uuid_bytes, "n": demo_bot.DEMO_BOT_NAME,
                 "a": demo_bot.DEMO_BOT_ABOUT, "c": demo_bot.DEMO_BOT_CODE},
            )
            print("Created demo contact.")
        db.commit()

        print("  uuid      :", demo_bot.DEMO_BOT_UUID)
        print("  peer code :", demo_bot.DEMO_BOT_CODE, "  <-- give this to App Review")
        print("  name      :", demo_bot.DEMO_BOT_NAME)
    finally:
        db.close()


if __name__ == "__main__":
    main()
