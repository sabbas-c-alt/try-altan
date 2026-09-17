"""
Service mesh registry. Run this first.
All other services discover each other through this registry.

Usage:
    python registry.py
"""

import json
import os
import ssl
import urllib.error
import urllib.request
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler

REGISTRY_PORT = 8500
HERE = os.path.dirname(os.path.abspath(__file__))
OP_CA_CERT_FILE = os.environ.get("CA_CERT_FILE", "op_ca_cert.pem")

# Services we know speak HTTPS (op-CA-signed).  Everything else is plain HTTP.
HTTPS_SERVICES = {"core", "IdentityCA"}


def _ts():
    return datetime.now().strftime("%H:%M:%S")
REGISTRY: dict[str, dict] = {}


class RegistryHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path == "/register":
            body = self._read_json()
            name = body["name"]
            REGISTRY[name] = {"host": body["host"], "port": body["port"]}
            print(f"{_ts()} [Registry] Registered: {name} -> {body['host']}:{body['port']}")
            self._respond(200, {"status": "registered", "name": name})
        else:
            self._respond(404, {"error": "unknown path"})

    def do_GET(self):
        if self.path.startswith("/lookup/"):
            name = self.path[len("/lookup/"):]
            if name in REGISTRY:
                self._respond(200, REGISTRY[name])
            else:
                print(f"{_ts()} [Registry] Lookup miss: {name}")
                self._respond(404, {"error": f"service '{name}' not registered"})
        elif self.path == "/services":
            self._respond(200, REGISTRY)
        elif self.path == "/" or self.path == "/dashboard":
            self._serve_file("index.html", "text/html; charset=utf-8")
        elif self.path == "/filefan":
            self._serve_file("dashboard.html", "text/html; charset=utf-8")
        elif self.path == "/core":
            self._serve_file("core_dashboard.html", "text/html; charset=utf-8")
        elif self.path == "/bee":
            self._serve_file("bee_dashboard.html", "text/html; charset=utf-8")
        elif self.path == "/registry":
            self._serve_file("registry_dashboard.html", "text/html; charset=utf-8")
        elif self.path == "/onprem":
            self._serve_file("onprem_dashboard.html", "text/html; charset=utf-8")
        elif self.path.startswith("/proxy/"):
            self._proxy(self.path[len("/proxy/"):])
        else:
            self._respond(404, {"error": "unknown path"})

    def _proxy(self, rest: str):
        # rest == "<service>/<path...>" — look up service in REGISTRY,
        # GET that URL, return body verbatim with CORS headers.
        parts = rest.split("/", 1)
        service = parts[0]
        sub_path = "/" + parts[1] if len(parts) > 1 else "/"
        if service not in REGISTRY:
            self._respond(404, {"error": f"service '{service}' not registered"})
            return
        target = REGISTRY[service]
        scheme = "https" if service in HTTPS_SERVICES else "http"
        url = f"{scheme}://{target['host']}:{target['port']}{sub_path}"
        try:
            ctx = None
            if scheme == "https":
                ctx = ssl.create_default_context(cafile=OP_CA_CERT_FILE) \
                      if os.path.exists(OP_CA_CERT_FILE) else ssl._create_unverified_context()
            with urllib.request.urlopen(url, timeout=10, context=ctx) as r:
                body = r.read()
                ct   = r.headers.get("Content-Type", "application/octet-stream")
                self.send_response(r.status)
                self.send_header("Content-Type", ct)
                self.send_header("Content-Length", str(len(body)))
                self._cors()
                self.end_headers()
                self.wfile.write(body)
        except urllib.error.HTTPError as e:
            self._respond(e.code, {"error": f"upstream {e.code}: {e.reason}"})
        except Exception as e:
            self._respond(502, {"error": f"proxy failure: {e}"})

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.end_headers()

    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def _serve_file(self, name: str, content_type: str):
        path = os.path.join(HERE, name)
        if not os.path.isfile(path):
            self._respond(404, {"error": f"{name} not found"})
            return
        with open(path, "rb") as f:
            body = f.read()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self._cors()
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self):
        length = int(self.headers["Content-Length"])
        return json.loads(self.rfile.read(length))

    def _respond(self, status: int, data: dict):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self._cors()
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass  # suppress default access log; we print our own


if __name__ == "__main__":
    print(f"{_ts()} ==============================")
    print(f"{_ts()} [Registry] START")
    print(f"{_ts()} ==============================")
    server = HTTPServer(("", REGISTRY_PORT), RegistryHandler)
    print(f"{_ts()} [Registry] Listening on port {REGISTRY_PORT}")
    print(f"{_ts()} [Registry] Endpoints: POST /register  GET /lookup/<name>  GET /services")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print(f"\n{_ts()} [Registry] Shutting down.")
