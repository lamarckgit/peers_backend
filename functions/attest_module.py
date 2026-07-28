# Device attestation for create_peer — the INVISIBLE primary "proof you're human" layer
# (pick-the-pear is the visible fallback; see response_module's human-challenge section).
#
# Flow: the client fetches a single-use NONCE (/v1/attest_nonce/), obtains a platform attestation
# for it — Apple App Attest (iOS/Mac) or Google Play Integrity (Android) — and presents it to
# /v1/verify_attest/. A successful verification yields a single-use ATTEST PASS that create_peer
# accepts in place of a pear answer. Every failure path simply leaves the client to fall back to
# the pear dialog, so a missing dependency / unreachable Google / unsupported device never blocks
# onboarding harder than the visible check does.
#
# All state is in-memory (single-worker event loop, like the relay's pending_ops): nonces and
# passes are single-use with short TTLs and capped FIFO.

import base64
import hashlib
import json
import os
import secrets
import time

import httpx

try:  # server-side crypto for App Attest chain verification; missing → App Attest verify fails soft
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec, padding
    _CRYPTO_OK = True
except Exception:  # pragma: no cover
    _CRYPTO_OK = False

try:
    import jwt as _jwt  # PyJWT (already used for APNs) — signs the Google service-account assertion
    _JWT_OK = True
except Exception:  # pragma: no cover
    _JWT_OK = False

# Apple App IDs allowed to attest (TEAMID.bundle_id) — iOS + Mac apps.
APP_ATTEST_APP_IDS = ["3V394W95NG.club.peers.ios", "3V394W95NG.club.peers.macos"]
# Google Play package allowed for Play Integrity.
PLAY_INTEGRITY_PACKAGE = "club.peers.android"
# Google service-account key (same file FCM uses; the GCP project must have the
# Play Integrity API enabled and the app linked in Play Console).
GOOGLE_SA_KEY_FILE = "serviceAccountKeyPeersClub.json"
# Apple's App Attest trust root — fetched once from Apple and cached beside the other static data.
APPLE_ROOT_URL = "https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem"
APPLE_ROOT_CACHE = "static/apple_app_attestation_root.pem"

NONCE_TTL_S = 300
PASS_TTL_S = 300
_STORE_CAP = 5000

_nonces: dict = {}   # nonce_id -> (nonce_hex, expires_ts)
_passes: dict = {}   # pass_token -> expires_ts


def _prune(store: dict):
    now = time.time()
    for k in [k for k, v in list(store.items()) if (v[1] if isinstance(v, tuple) else v) < now]:
        store.pop(k, None)
    while len(store) >= _STORE_CAP:
        store.pop(next(iter(store)), None)


def issue_nonce() -> dict:
    """A fresh single-use attestation nonce. The client feeds it (utf-8 of the hex string) into
    App Attest's clientDataHash / Play Integrity's nonce, so replays can't reuse a verification."""
    _prune(_nonces)
    nonce_id = secrets.token_hex(16)
    nonce = secrets.token_hex(32)
    _nonces[nonce_id] = (nonce, time.time() + NONCE_TTL_S)
    return {"success": True, "nonce_id": nonce_id, "nonce": nonce}


def _consume_nonce(nonce_id: str):
    entry = _nonces.pop(nonce_id or "", None)
    if entry is None or entry[1] < time.time():
        return None
    return entry[0]


def _issue_pass() -> str:
    _prune(_passes)
    token = secrets.token_hex(24)
    _passes[token] = time.time() + PASS_TTL_S
    return token


def consume_attest_pass(token: str) -> bool:
    """Single-use redemption by create_peer."""
    expires = _passes.pop(token or "", None)
    return expires is not None and time.time() <= expires


def verify(nonce_id: str, platform: str, key_id: str = "", attestation: str = "",
           integrity_token: str = "") -> dict:
    """Verify a platform attestation for a live nonce → {"success": True, "attest_pass": ...} or
    {"success": False, "error": ...}. The nonce is consumed either way (single-use)."""
    nonce = _consume_nonce(nonce_id)
    if nonce is None:
        return {"success": False, "error": "unknown or expired nonce"}
    try:
        if platform == "apple":
            ok, why = _verify_app_attest(key_id, attestation, nonce)
        elif platform == "android":
            ok, why = _verify_play_integrity(integrity_token, nonce)
        else:
            ok, why = False, "unknown platform"
    except Exception as e:
        ok, why = False, f"verify error: {e}"
    if not ok:
        print(f"attest: {platform} verification FAILED — {why}")
        return {"success": False, "error": why}
    return {"success": True, "attest_pass": _issue_pass()}


# ---- Apple App Attest ---------------------------------------------------------------------------

def _cbor_decode(data: bytes, offset: int = 0):
    """Minimal CBOR decoder covering the App Attest attestation object (maps, arrays, byte/text
    strings, ints). Returns (value, next_offset)."""
    if offset >= len(data):
        raise ValueError("cbor: truncated")
    b = data[offset]
    major, info = b >> 5, b & 0x1F
    offset += 1
    if info < 24:
        length = info
    elif info == 24:
        length = data[offset]; offset += 1
    elif info == 25:
        length = int.from_bytes(data[offset:offset + 2], "big"); offset += 2
    elif info == 26:
        length = int.from_bytes(data[offset:offset + 4], "big"); offset += 4
    elif info == 27:
        length = int.from_bytes(data[offset:offset + 8], "big"); offset += 8
    else:
        raise ValueError("cbor: unsupported length encoding")
    if major == 0:
        return length, offset
    if major == 1:
        return -1 - length, offset
    if major == 2:
        return data[offset:offset + length], offset + length
    if major == 3:
        return data[offset:offset + length].decode("utf-8"), offset + length
    if major == 4:
        items = []
        for _ in range(length):
            v, offset = _cbor_decode(data, offset)
            items.append(v)
        return items, offset
    if major == 5:
        m = {}
        for _ in range(length):
            k, offset = _cbor_decode(data, offset)
            v, offset = _cbor_decode(data, offset)
            m[k] = v
        return m, offset
    if major == 6:  # tag — unwrap
        return _cbor_decode(data, offset)
    raise ValueError(f"cbor: unsupported major type {major}")


def _apple_root_cert():
    """Apple's App Attestation Root CA, fetched once over TLS from apple.com and cached on disk."""
    if not os.path.exists(APPLE_ROOT_CACHE):
        pem = httpx.get(APPLE_ROOT_URL, timeout=10).content
        os.makedirs(os.path.dirname(APPLE_ROOT_CACHE), exist_ok=True)
        with open(APPLE_ROOT_CACHE, "wb") as f:
            f.write(pem)
    with open(APPLE_ROOT_CACHE, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


def _verify_cert_signed_by(cert, issuer):
    pub = issuer.public_key()
    if isinstance(pub, ec.EllipticCurvePublicKey):
        pub.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(cert.signature_hash_algorithm))
    else:  # RSA fallback (not expected for App Attest, but harmless)
        pub.verify(cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), cert.signature_hash_algorithm)


def _verify_app_attest(key_id_b64: str, attestation_b64: str, nonce: str):
    """Full server-side App Attest attestation verification per Apple's docs: cert chain to Apple's
    root, nonce binding, key-id binding, and authenticator-data checks against our App IDs."""
    if not _CRYPTO_OK:
        return False, "cryptography library unavailable"
    try:
        att = base64.b64decode(attestation_b64)
        key_id = base64.b64decode(key_id_b64)
    except Exception:
        return False, "bad base64"
    obj, _ = _cbor_decode(att)
    if obj.get("fmt") != "apple-appattest":
        return False, "not an apple-appattest object"
    x5c = obj.get("attStmt", {}).get("x5c") or []
    auth_data = obj.get("authData")
    if len(x5c) < 2 or not isinstance(auth_data, (bytes, bytearray)):
        return False, "malformed attestation"

    cred_cert = x509.load_der_x509_certificate(bytes(x5c[0]))
    ca_cert = x509.load_der_x509_certificate(bytes(x5c[1]))
    root = _apple_root_cert()

    # 1. Chain: credCert ← intermediate ← Apple root (signatures + validity windows).
    try:
        _verify_cert_signed_by(cred_cert, ca_cert)
        _verify_cert_signed_by(ca_cert, root)
    except Exception:
        return False, "certificate chain invalid"
    now = time.time()
    for c in (cred_cert, ca_cert):
        try:
            # The _utc properties (cryptography 42+) return AWARE datetimes; the deprecated naive
            # ones would be interpreted in the server's LOCAL timezone by .timestamp().
            nvb, nva = c.not_valid_before_utc.timestamp(), c.not_valid_after_utc.timestamp()
        except AttributeError:  # older cryptography
            nvb, nva = c.not_valid_before.timestamp(), c.not_valid_after.timestamp()
        if not (nvb <= now <= nva):
            return False, "certificate expired"

    # 2. Nonce binding: SHA256(authData ‖ SHA256(nonce)) must appear in credCert's Apple extension
    #    (OID 1.2.840.113635.100.8.2 — DER wrapping a 32-byte OCTET STRING).
    client_data_hash = hashlib.sha256(nonce.encode()).digest()
    expected = hashlib.sha256(bytes(auth_data) + client_data_hash).digest()
    ext_der = None
    for ext in cred_cert.extensions:
        if ext.oid.dotted_string == "1.2.840.113635.100.8.2":
            ext_der = ext.value.value if hasattr(ext.value, "value") else None
    if not ext_der:
        return False, "attestation extension missing"
    marker = ext_der.find(b"\x04\x20")   # OCTET STRING, length 32
    if marker < 0 or ext_der[marker + 2:marker + 34] != expected:
        return False, "nonce mismatch"

    # 3. Key id = SHA256 of the credential public key (uncompressed point).
    pub_bytes = cred_cert.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    if hashlib.sha256(pub_bytes).digest() != key_id:
        return False, "key id mismatch"

    # 4. Authenticator data: our App ID hash, counter 0, App Attest aaguid, credential id = key id.
    ad = bytes(auth_data)
    if len(ad) < 55:
        return False, "authData too short"
    if ad[:32] not in [hashlib.sha256(a.encode()).digest() for a in APP_ATTEST_APP_IDS]:
        return False, "app id mismatch"
    if int.from_bytes(ad[33:37], "big") != 0:
        return False, "counter not zero"
    if ad[37:53] not in (b"appattest\x00\x00\x00\x00\x00\x00\x00", b"appattestdevelop"):
        return False, "not an App Attest aaguid"
    cred_id_len = int.from_bytes(ad[53:55], "big")
    if ad[55:55 + cred_id_len] != key_id:
        return False, "credential id mismatch"
    return True, ""


# ---- Google Play Integrity ----------------------------------------------------------------------

_google_token: dict = {"token": "", "expires": 0.0}


def _google_access_token():
    """OAuth2 access token for the Play Integrity scope via the FCM service-account key (JWT
    bearer grant). Cached until shortly before expiry."""
    if _google_token["token"] and time.time() < _google_token["expires"] - 60:
        return _google_token["token"]
    if not _JWT_OK:
        raise RuntimeError("PyJWT unavailable")
    with open(GOOGLE_SA_KEY_FILE) as f:
        sa = json.load(f)
    now = int(time.time())
    assertion = _jwt.encode(
        {"iss": sa["client_email"], "scope": "https://www.googleapis.com/auth/playintegrity",
         "aud": sa["token_uri"], "iat": now, "exp": now + 3600},
        sa["private_key"], algorithm="RS256")
    resp = httpx.post(sa["token_uri"], data={
        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": assertion,
    }, timeout=10)
    resp.raise_for_status()
    data = resp.json()
    _google_token["token"] = data["access_token"]
    _google_token["expires"] = time.time() + int(data.get("expires_in", 3600))
    return _google_token["token"]


def _verify_play_integrity(integrity_token: str, nonce: str):
    """Decode the Play Integrity token via Google's API and check nonce, package, freshness and
    the device-integrity verdict (the bot gate; the app verdict is logged but not required, so
    sideloaded dev builds on real devices still pass)."""
    if not integrity_token:
        return False, "no integrity token"
    token = _google_access_token()
    resp = httpx.post(
        f"https://playintegrity.googleapis.com/v1/{PLAY_INTEGRITY_PACKAGE}:decodeIntegrityToken",
        json={"integrityToken": integrity_token},
        headers={"Authorization": f"Bearer {token}"}, timeout=10)
    if resp.status_code != 200:
        return False, f"decode failed ({resp.status_code})"
    payload = resp.json().get("tokenPayloadExternal", {})
    req = payload.get("requestDetails", {})
    if req.get("nonce") != nonce:
        return False, "nonce mismatch"
    if req.get("requestPackageName") != PLAY_INTEGRITY_PACKAGE:
        return False, "package mismatch"
    ts = int(req.get("timestampMillis", 0))
    if abs(time.time() * 1000 - ts) > 10 * 60 * 1000:
        return False, "stale token"
    device = payload.get("deviceIntegrity", {}).get("deviceRecognitionVerdict", [])
    if "MEETS_DEVICE_INTEGRITY" not in device:
        return False, f"device verdict {device}"
    app_verdict = payload.get("appIntegrity", {}).get("appRecognitionVerdict", "")
    if app_verdict != "PLAY_RECOGNIZED":
        print(f"attest: play integrity app verdict {app_verdict} (device ok — allowed)")
    return True, ""
