"""Stdlib HTTP server for the local triage dashboard.

Binds to localhost by default. Uploaded bytes are analysed in-process (never
executed) and optionally persisted to the corpus. No third-party web framework.
"""

from __future__ import annotations

import json
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from ..core.analyzer import Analyzer
from ..corpus import Corpus
from .page import PAGE

_MAX_UPLOAD = 64 * 1024 * 1024


def serve(host: str = "127.0.0.1", port: int = 8710, db_path: str = None,
          rule_paths=None, deep_code: bool = True):
    analyzer = Analyzer(extra_rule_paths=rule_paths, deep_code=deep_code)
    corpus = Corpus(db_path) if db_path else Corpus()

    class Handler(BaseHTTPRequestHandler):
        server_version = "Strix/0.2"

        def log_message(self, *a):  # quiet
            pass

        def _send(self, code, body, ctype="application/json"):
            if isinstance(body, (dict, list)):
                body = json.dumps(body, default=str).encode()
            elif isinstance(body, str):
                body = body.encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            path = urllib.parse.urlparse(self.path).path
            if path == "/" or path == "/index.html":
                return self._send(200, PAGE, "text/html; charset=utf-8")
            if path == "/api/corpus":
                rows = [dict(r) for r in corpus.all(500)]
                return self._send(200, {"samples": rows, "stats": corpus.stats()})
            if path == "/api/clusters":
                clusters = [[dict(r) for r in g] for g in corpus.cluster()]
                return self._send(200, {"clusters": clusters})
            return self._send(404, {"error": "not found"})

        def do_POST(self):
            path = urllib.parse.urlparse(self.path).path
            qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            if path != "/api/scan":
                return self._send(404, {"error": "not found"})
            length = int(self.headers.get("Content-Length", 0))
            if length <= 0 or length > _MAX_UPLOAD:
                return self._send(413, {"error": "bad upload size"})
            data = self.rfile.read(length)
            fname = urllib.parse.unquote(self.headers.get("X-Filename", "upload.bin"))
            try:
                report = analyzer.analyze_bytes(data, path=fname)
            except Exception as exc:
                return self._send(500, {"error": f"analysis failed: {exc!r}"})
            if qs.get("save", ["1"])[0] == "1":
                try:
                    corpus.add(report)
                except Exception:
                    pass
            return self._send(200, report.to_dict())

    httpd = ThreadingHTTPServer((host, port), Handler)
    url = f"http://{host}:{port}/"
    print(f"Strix triage console → {url}  (Ctrl-C to stop)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopping.")
    finally:
        httpd.server_close()
        corpus.close()
    return url
