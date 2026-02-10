from servers.ApacheServer import ApacheServer
from urllib.parse import parse_qs
import os
import hashlib

SITE_DIR = os.path.join(os.path.dirname(__file__), "..", "site")

def read_file(name: str) -> str:
    with open(os.path.join(SITE_DIR, name), "r", encoding="utf-8", errors="ignore") as f:
        return f.read()

def hash_pw(pw: str) -> str:
    # Don’t store raw passwords—store a short hash for analysis
    return hashlib.sha256(pw.encode("utf-8", errors="ignore")).hexdigest()[:16]

class LoginSiteServer(ApacheServer):
    def on_request(self, handler):
        return None, None

    def on_GET(self, path, headers):
        # Normalize
        if path == "/":
            body = read_file("index.html")
            return 200, [("Content-Type", "text/html; charset=utf-8")], body

        if path == "/createacc.html":
            body = read_file("createacc.html")
            return 200, [("Content-Type", "text/html; charset=utf-8")], body

        if path == "/standin.html":
            body = read_file("standin.html")
            return 200, [("Content-Type", "text/html; charset=utf-8")], body

        if path == "/style.css":
            body = read_file("style.css")
            return 200, [("Content-Type", "text/css; charset=utf-8")], body

        if path == "/favicon.ico":
            return 204, [], ""  # no content, avoids noisy 404s
        
        if path.endswith(".py"):
            return 404, [("Content-Type","text/plain; charset=utf-8")], "Not Found"


        return 404, [("Content-Type", "text/plain; charset=utf-8")], "Not Found"

    def on_POST(self, path, headers, post_data):
        # post_data is raw form bytes/string; we parse it as x-www-form-urlencoded
        raw = post_data.decode("utf-8", errors="ignore") if isinstance(post_data, (bytes, bytearray)) else str(post_data)
        fields = parse_qs(raw)

        extra = {"form_path": path}

        if path == "/login":
            user = (fields.get("username") or fields.get("login") or [""])[0]
            pw = (fields.get("password") or [""])[0]
            extra["login_user"] = user
            extra["login_pw_hash"] = hash_pw(pw)
            extra["login_pw_len"] = len(pw)

            #could chnage to show return result from log in instead
            body = read_file("standin.html")
            self._last_extra = extra
            return 200, [("Content-Type", "text/html; charset=utf-8")], body

        if path == "/create":
            username = (fields.get("username") or [""])[0]
            email = (fields.get("email") or [""])[0]
            pw = (fields.get("password") or [""])[0]
            extra["create_user"] = username
            extra["create_email"] = email
            extra["create_pw_hash"] = hash_pw(pw)
            extra["create_pw_len"] = len(pw)

            #could chnage to show return result from log in instead
            body = read_file("standin.html")
            self._last_extra = extra
            return 200, [("Content-Type", "text/html; charset=utf-8")], body

        self._last_extra = {"form_path": path, "note": "unknown_post"}
        return 404, [("Content-Type", "text/plain; charset=utf-8")], "Not Found"

    def on_error(self, code, headers, message):
        return code, [("Connection", "close"), ("Content-Type", "text/html; charset=utf-8")], message

    def on_complete(self, client, code, req_headers, res_headers, request, response):
        # Attach extra info from the last POST handler call if present
        extra = getattr(self, "_last_extra", {})
        self._last_extra = {}
        self.log(client, request, response, extra)

    def default_headers(self):
        return []
