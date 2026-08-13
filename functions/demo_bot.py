"""
functions/demo_bot.py — App Store review demo contact (the "demo bot").

FULLY ISOLATED from normal operation. Every code path in this module is reached ONLY
when a relay frame's `target` is the single reserved demo peer (DEMO_BOT_UUID). For
every real peer, main.py's relay never calls into here, so behaviour is unchanged.
This module adds no endpoint, no schema change, and no change to the wire protocol.

Purpose: let an App Review tester experience PEERS.CLUB's friends-based, consent-only
model from ONE device. The tester types the demo peer code (DEMO_BOT_CODE) under
Friends > Add Friend; this module auto-accepts the friend request exactly as a human
would (persist via add_friend + return FRIEND_ACCEPT), then chats back to messages and
declines calls cleanly.

Kill switch: set env PEERS_DEMO_BOT_ENABLED=0 (or PEERS_DEMO_BOT_UUID="") — is_demo_target
then always returns False and the relay behaves as if this module did not exist.

Seed the demo peer's `user` row + public code once with:
    python -m functions.seed_demo_bot
"""

import os
import uuid
import random
import asyncio

from functions import response_module

# --- Reserved identity (env-overridable; the defaults are safe fixed constants) -----
DEMO_BOT_UUID = (os.environ.get("PEERS_DEMO_BOT_UUID")
                 or "de30de30de30de30de30de30de30de30").strip().lower()
DEMO_BOT_CODE = os.environ.get("PEERS_DEMO_BOT_CODE") or "PEERS1"
DEMO_BOT_NAME = os.environ.get("PEERS_DEMO_BOT_NAME") or "PEERS.CLUB Demo"
DEMO_BOT_ABOUT = (os.environ.get("PEERS_DEMO_BOT_ABOUT")
                  or "Demo contact for App Review. Say hi — I only reply to people who added my code.")
DEMO_BOT_ENABLED = os.environ.get("PEERS_DEMO_BOT_ENABLED", "1") != "0"

# The greeting the tester sees the moment we become friends — so they open a populated chat.
_WELCOME = [
    "👋 Welcome to PEERS.CLUB! We're connected only because you entered my code — "
    "there is no random or anonymous matching anywhere in this app.",
    "This is a private one-to-one chat. Try a message, a photo, your location, or a contact "
    "with the ➕ button — or start a voice/video call from the top bar.",
]

# Rotating replies to a plain text message. Each reinforces a real, reviewable feature.
_REPLIES = [
    "Nice — that arrived as a private message between two people who chose to connect. 🙂",
    "PEERS.CLUB only links people who have exchanged codes, so every chat is consent-based.",
    "You can Report or Block any contact from their profile — tap my name at the top to see them.",
    "You can delete individual messages, clear this whole chat, or delete your profile from Settings.",
    "Got it! Feel free to try a photo or a voice message next.",
]


def is_demo_target(target_id: str) -> bool:
    """True for the one reserved demo peer only. Guards the single hook in main.py, so a False
    here means the relay runs its normal path completely unaffected by this module."""
    if not DEMO_BOT_ENABLED or not DEMO_BOT_UUID or not target_id:
        return False
    return target_id.strip().lower() == DEMO_BOT_UUID


def _frame(msg_type: str, target: str, **extra) -> dict:
    """A relay frame as it would look after the relay stamps `sender` — here the sender is the bot."""
    frame = {"type": msg_type, "sender": DEMO_BOT_UUID, "senderDevice": "demo", "target": target}
    frame.update(extra)
    return frame


async def _say(manager, reviewer_id: str, text: str):
    """Deliver one chat message from the bot. Also queued (de-duped by msgId on the client) so a
    momentary socket blip during review still lands the message on reconnect."""
    frame = _frame("CHAT_MESSAGE", reviewer_id, text=text, msgId=uuid.uuid4().hex)
    try:
        manager.enqueue(reviewer_id, frame)
    except Exception:
        pass
    await manager.send_all(reviewer_id, frame)


async def _greet(manager, reviewer_id: str):
    """Delayed, ordered greeting sent AFTER FRIEND_ACCEPT so the tester is already a friend when
    these arrive (friends' messages are stored silently with a badge)."""
    try:
        for i, line in enumerate(_WELCOME):
            await asyncio.sleep(0.6 if i == 0 else 1.2)
            await _say(manager, reviewer_id, line)
    except Exception as e:
        print(f"demo_bot: greet error: {e}")


async def _reply_to_message(manager, reviewer_id: str, data: dict):
    """A short 'typing' pause, then a context-aware reply to whatever the tester sent."""
    try:
        await asyncio.sleep(0.7)
        if data.get("imageData"):
            reply = "Got your photo — nicely delivered over the private chat. 📷"
        elif data.get("audioData"):
            reply = "Heard your voice message loud and clear. 🎙️"
        elif data.get("latitude") is not None:
            reply = "Thanks for sharing your location — only your chosen contacts can ever see it. 📍"
        elif data.get("contactCard"):
            reply = "Thanks for the contact card. 👤"
        else:
            reply = random.choice(_REPLIES)
        await _say(manager, reviewer_id, reply)
    except Exception as e:
        print(f"demo_bot: reply error: {e}")


async def _explain_call(manager, reviewer_id: str):
    try:
        await asyncio.sleep(0.3)
        await _say(manager, reviewer_id,
                   "Calls in PEERS.CLUB connect two real people, so this demo contact can't pick up. "
                   "The review notes include a short video of a live audio/video call.")
    except Exception as e:
        print(f"demo_bot: call-explain error: {e}")


async def handle_frame(manager, database, sender_id: str, sender_device: str, data: dict):
    """Handle a frame the tester addressed to the demo peer. Called from main.py's relay ONLY when
    is_demo_target(target) is True. Never raises into the relay loop; long replies run as background
    tasks so the tester's receive loop is not blocked."""
    try:
        msg_type = data.get("type")
        reviewer = sender_id
        # Ignore self-addressed / malformed frames.
        if not reviewer or reviewer.strip().lower() == DEMO_BOT_UUID:
            return

        if msg_type == "FRIEND_REQUEST":
            # Persist the friendship exactly as a human accepter's device would (add_friend),
            # then flip the tester's UI to "friends" (FRIEND_ACCEPT), then greet.
            db = database.create_session()
            try:
                response_module.add_friend(db, DEMO_BOT_UUID, reviewer)
            except Exception as e:
                print(f"demo_bot: add_friend failed: {e}")
            finally:
                db.close()
            await manager.send_all(reviewer, _frame("FRIEND_ACCEPT", reviewer, text=DEMO_BOT_NAME))
            asyncio.create_task(_greet(manager, reviewer))
            return

        if msg_type == "CHAT_REQUEST":
            # Defensive only: reached if a tester opens a chat before befriending. Accept it.
            await manager.send_all(reviewer, _frame("CHAT_ACCEPT", reviewer, text=DEMO_BOT_NAME))
            return

        if msg_type == "CHAT_MESSAGE":
            asyncio.create_task(_reply_to_message(manager, reviewer, data))
            return

        if msg_type == "CALL_REQUEST":
            # A backend contact can't carry live WebRTC media — decline cleanly (no endless ring)
            # and explain, rather than leave the tester's call screen hanging.
            await manager.send_all(reviewer, _frame("CALL_REJECT", reviewer))
            asyncio.create_task(_explain_call(manager, reviewer))
            return

        # CHAT_READ / CHAT_CLOSE / CHAT_ACCEPT_ACK / CALL_* / anything else: nothing to do.
    except Exception as e:
        print(f"demo_bot: handle_frame error: {e}")
