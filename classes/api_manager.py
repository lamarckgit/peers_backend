import httpx


class ApiManager:
    """Generic HTTP client for posting JSON payloads and receiving raw bytes.

    Kept deliberately free of any license-specific knowledge so it can be reused
    by any caller that needs to POST JSON and read back an octet-stream body.
    """

    def __init__(self, verify_tls: bool = True):
        # Verify the peer's TLS cert by default. Callers may opt out (e.g. for
        # local/dev) by passing verify_tls=False; never do so in production.
        self.verify_tls = verify_tls

    def api_post(self, url, payload, api_key: str = ""):
        headers = {
            "accept": "application/octet-stream",
            "Content-Type": "application/json",
            "X-API-Key": api_key,
        }
        with httpx.Client(verify=self.verify_tls) as client:
            resp = client.post(url, headers=headers, json=payload)
            resp.raise_for_status()
            return resp.content

    def api_post1(self, url, payload):
        headers = {
            "accept": "application/json",  # application/octet-stream → caused 406
            "Content-Type": "application/json",
        }
        with httpx.Client(verify=self.verify_tls) as client:
            resp = client.post(url, headers=headers, json=payload)
            resp.raise_for_status()
            return resp.content
