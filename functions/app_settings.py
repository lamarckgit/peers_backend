"""App-wide feature settings served to the clients (`POST /v1/settings/`).

Source today: `settings.json` next to main.py (re-read when its mtime changes). Next step: the
licence server delivers them in constants.json.enc — a constant of the same UPPER_CASE name there
overrides the file, so nothing in the clients changes when that lands.

  bluetooth_discovery     A: Bluetooth (nearby) discovery is part of this system at all. Off → the
                          apps hide Souverains Nearby + Map and the discovery toggles, and skip the
                          Bluetooth permission steps in onboarding (a pure messenger).
  cross_system_discovery  B: members of THIS system may be discovered over Bluetooth by members of
                          the OTHER systems configured in their app (and vice versa). Only meaningful
                          with more than one system; the app shows an opt-out toggle for it.
"""
import json
import os
import threading

_DEFAULTS = {
    "bluetooth_discovery": True,
    "cross_system_discovery": True,
}
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SETTINGS_PATH = os.environ.get("APP_SETTINGS_PATH", os.path.join(_ROOT, "settings.json"))
_cache = {"mtime": None, "values": dict(_DEFAULTS)}
_lock = threading.Lock()


def _read_file():
    try:
        mtime = os.path.getmtime(SETTINGS_PATH)
    except OSError:
        return None, {}
    with open(SETTINGS_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    return mtime, {k: bool(v) for k, v in data.items() if k in _DEFAULTS}


def get_app_settings(constants: dict = None) -> dict:
    """The effective settings: defaults ← settings.json ← licence constants (UPPER_CASE keys)."""
    with _lock:
        try:
            mtime, values = _read_file()
            if mtime != _cache["mtime"]:
                _cache["mtime"] = mtime
                _cache["values"] = {**_DEFAULTS, **values}
                print(f"app settings loaded: {_cache['values']}")
        except Exception as e:
            print(f"app settings: could not read {SETTINGS_PATH}: {e} — keeping {_cache['values']}")
        result = dict(_cache["values"])
    for key in _DEFAULTS:
        if constants and key.upper() in constants:
            result[key] = bool(constants[key.upper()])
    return result
