"""Integration checks for the Windows executable; no third-party Python packages.

Creates temporary CurrentUser/My certificates for HTTPS tests, removes them and
their private keys afterward, and never adds a system trust entry/firewall rule.
Run: python tools/verify_security.py
"""
import concurrent.futures
import hashlib
import http.client
import os
from pathlib import Path
import re
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
import unittest
from urllib.parse import quote, urlencode

PROJECT = Path(__file__).resolve().parents[1]
EXECUTABLE = PROJECT / "sharehub.exe"


def powershell(script):
    result = subprocess.run(["powershell", "-NoProfile", "-Command", script],
                            capture_output=True, text=True, encoding="utf-8", errors="replace")
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    return result.stdout.strip()


class Server:
    def __init__(self, mode="basic", extra=()):
        self.temp = tempfile.TemporaryDirectory(prefix="sharehub-security-")
        self.work = Path(self.temp.name)
        self.root = self.work / "share"
        self.root.mkdir()
        self.process = None
        self.thumbprints = []
        self.mode = mode
        self.context = None
        try:
            if mode == "secure":
                script = self.work / "setup-https.ps1"
                shutil.copyfile(PROJECT / script.name, script)
                result = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script), "-IpAddress", "127.0.0.1"], capture_output=True)
                if result.returncode:
                    raise RuntimeError(result.stdout.decode(errors="replace") + result.stderr.decode(errors="replace"))
                self.thumbprints.append((self.work / "tls-cert.txt").read_text().strip())
                cert_path = str(self.work / "root-cert.cer").replace("'", "''")
                root_id = powershell("$c=New-Object System.Security.Cryptography.X509Certificates.X509Certificate2('" + cert_path + "'); $c.Thumbprint")
                self.thumbprints.append(root_id)
                root_pem = ssl.DER_cert_to_PEM_cert((self.work / "root-cert.cer").read_bytes())
                self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                self.context.load_verify_locations(cadata=root_pem)
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", 0))
                self.port = probe.getsockname()[1]
            self.origin = f"{'https' if mode == 'secure' else 'http'}://127.0.0.1:{self.port}"
            self.process = subprocess.Popen([str(EXECUTABLE), "--mode", mode, "--bind", "127.0.0.1", "--folder", str(self.root), "--port", str(self.port), *extra],
                                            cwd=self.work, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                            text=True, encoding="utf-8", errors="replace")
            self.lines = []
            for _ in range(20):
                line = self.process.stdout.readline()
                if not line:
                    raise RuntimeError("Server did not start: " + "".join(self.lines))
                self.lines.append(line)
                if line.startswith("Pairing code: "):
                    self.code = line.split(": ", 1)[1].strip()
                    break
            else:
                raise RuntimeError("Pairing code not printed")
        except Exception:
            self.close()
            raise

    def connection(self):
        if self.mode == "secure":
            return http.client.HTTPSConnection("127.0.0.1", self.port, context=self.context, timeout=10)
        return http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)

    def request(self, method, path, body=None, headers=None):
        connection = self.connection()
        try:
            values = dict(headers or {})
            if method == "POST":
                values.setdefault("Origin", self.origin)
            connection.request(method, path, body=body, headers=values)
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def login(self):
        status, headers, body = self.request("POST", "/login", urlencode({"code": self.code}), {"Content-Type": "application/x-www-form-urlencoded"})
        assert status == 303, (status, body)
        self.cookie = headers["Set-Cookie"].split(";", 1)[0]
        status, _, page = self.request("GET", "/browse", headers={"Cookie": self.cookie})
        assert status == 200, page
        self.csrf = re.search(rb"data-csrf='([a-f0-9]+)'", page).group(1).decode()
        return headers, page

    def upload(self, name, body, **headers):
        headers.setdefault("Cookie", self.cookie)
        headers.setdefault("X-CSRF-Token", self.csrf)
        return self.request("POST", "/api/upload?path=" + quote(name, safe=""), body, headers)

    def raw(self, request):
        with socket.create_connection(("127.0.0.1", self.port), timeout=10) as socket_:
            if self.mode == "secure":
                socket_ = self.context.wrap_socket(socket_, server_hostname="127.0.0.1")
            with socket_:
                socket_.sendall(request)
                result = b""
                while True:
                    piece = socket_.recv(65536)
                    if not piece:
                        return result
                    result += piece

    def close(self):
        if self.process:
            self.process.terminate()
            self.process.wait(timeout=10)
            self.process.stdout.close()
        for thumbprint in self.thumbprints:
            if re.fullmatch(r"[A-Fa-f0-9]{40}", thumbprint):
                powershell("Remove-Item -LiteralPath 'Cert:\\CurrentUser\\My\\" + thumbprint + "' -DeleteKey -ErrorAction SilentlyContinue")
        self.temp.cleanup()


class SecurityChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = Server()
        cls.login_headers, cls.page = cls.server.login()

    @classmethod
    def tearDownClass(cls):
        cls.server.close()

    def test_01_authentication_and_cookie(self):
        s = self.server
        self.assertEqual(s.request("GET", "/download?path=secret.txt")[0], 401)
        self.assertEqual(s.request("GET", "/")[0], 200)
        cookie = self.login_headers["Set-Cookie"]
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Strict", cookie)
        self.assertIn("Max-Age=1800", cookie)
        self.assertNotIn(s.code.encode(), self.page)
        self.assertIn("비보안 모드".encode(), self.page)

    def test_02_csrf_and_host(self):
        s = self.server
        self.assertEqual(s.upload("csrf.bin", b"x", **{"X-CSRF-Token": "bad"})[0], 403)
        self.assertEqual(s.upload("origin.bin", b"x", Origin="https://attacker.invalid")[0], 403)
        self.assertEqual(s.request("GET", "/browse", headers={"Cookie": s.cookie, "Host": "attacker.invalid"})[0], 403)
        self.assertFalse((s.root / "csrf.bin").exists())

    def test_03_transfer_and_no_overwrite(self):
        s = self.server
        data = os.urandom(8 * 1024 * 1024)
        name = "nested/파일 ' sample.bin"
        start = time.perf_counter()
        self.assertEqual(s.upload(name, data)[0], 201)
        status, headers, result = s.request("GET", "/download?path=" + quote(name, safe=""), headers={"Cookie": s.cookie})
        self.assertEqual(status, 200)
        self.assertEqual(hashlib.sha256(result).digest(), hashlib.sha256(data).digest())
        self.assertIn("attachment", headers["Content-Disposition"])
        self.assertEqual(s.upload(name, b"overwrite")[0], 409)
        self.assertEqual((s.root / name).read_bytes(), data)
        print(f"Basic loopback round trip: {len(data) * 2 / (time.perf_counter() - start) / 1048576:.1f} MiB/s (not a Wi-Fi benchmark)")

    def test_04_paths_and_links(self):
        s = self.server
        for name in ["../outside.txt", "C:/outside.txt", "\\\\server\\share", "file:stream", "CON.txt", "LPT1", "trailing. ", ".sharehub-secret", "folder/../bad"]:
            with self.subTest(name=name):
                self.assertIn(s.upload(name, b"forbidden")[0], (400, 403))
        self.assertEqual(s.request("GET", "/download?path=%FF", headers={"Cookie": s.cookie})[0], 400)
        outside = s.work / "outside"
        outside.mkdir(exist_ok=True)
        (outside / "secret.bin").write_bytes(b"outside secret")
        os.link(outside / "secret.bin", s.root / "hardlink.bin")
        self.assertEqual(s.request("GET", "/download?path=hardlink.bin", headers={"Cookie": s.cookie})[0], 403)
        result = subprocess.run(["cmd", "/c", "mklink", "/J", str(s.root / "junction"), str(outside)], capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(s.upload("junction/new.bin", b"outside write")[0], 403)
        self.assertEqual(s.request("GET", "/download?path=junction%2Fsecret.bin", headers={"Cookie": s.cookie})[0], 403)
        self.assertFalse((outside / "new.bin").exists())

    def test_05_interrupted_upload(self):
        s = self.server
        request = (f"POST /api/upload?path=incomplete.bin HTTP/1.1\r\nHost: 127.0.0.1:{s.port}\r\nOrigin: {s.origin}\r\nCookie: {s.cookie}\r\nX-CSRF-Token: {s.csrf}\r\nContent-Length: 1048576\r\n\r\n").encode()
        with socket.create_connection(("127.0.0.1", s.port), timeout=5) as connection:
            connection.sendall(request + b"only a fragment")
        time.sleep(0.2)
        self.assertFalse((s.root / "incomplete.bin").exists())
        self.assertFalse(list(s.root.glob(".sharehub-upload-*")))

    def test_06_malformed_http(self):
        s = self.server
        cases = [
            (f"POST /login HTTP/1.1\r\nHost: 127.0.0.1:{s.port}\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nx", 400),
            (f"POST /login HTTP/1.1\r\nHost: 127.0.0.1:{s.port}\r\nTransfer-Encoding: chunked\r\n\r\n", 400),
            (f"POST /login HTTP/1.1\r\nHost: 127.0.0.1:{s.port}\r\nContent-Length: 2147483649\r\n\r\n", 413),
            (f"GET / HTTP/1.1\r\nHost: 127.0.0.1:{s.port}\r\nX-Long: " + "x" * 20000 + "\r\n\r\n", 431),
        ]
        for request, status in cases:
            with self.subTest(status=status):
                self.assertTrue(s.raw(request.encode()).startswith(f"HTTP/1.1 {status}".encode()))

    def test_07_concurrent_uploads(self):
        s = self.server
        data = os.urandom(1024 * 1024)
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            responses = list(pool.map(lambda i: s.upload(f"parallel-{i}.bin", data), range(4)))
        self.assertEqual([r[0] for r in responses], [201] * 4)
        for i in range(4):
            self.assertEqual((s.root / f"parallel-{i}.bin").read_bytes(), data)

    def test_08_rate_limit_and_logout(self):
        s = self.server
        for _ in range(5):
            self.assertEqual(s.request("POST", "/login", "code=wrong", {"Content-Type": "application/x-www-form-urlencoded"})[0], 401)
        self.assertEqual(s.request("POST", "/login", urlencode({"code": s.code}), {"Content-Type": "application/x-www-form-urlencoded"})[0], 429)
        self.assertEqual(s.request("POST", "/logout", b"", {"Cookie": s.cookie, "X-CSRF-Token": s.csrf})[0], 200)
        self.assertEqual(s.request("GET", "/download?path=parallel-0.bin", headers={"Cookie": s.cookie})[0], 401)

    def test_09_read_only(self):
        s = Server(extra=("--read-only",))
        try:
            s.login()
            self.assertEqual(s.upload("denied.bin", b"x")[0], 403)
        finally:
            s.close()

    def test_10_https_mode(self):
        s = Server(mode="secure")
        try:
            headers, page = s.login()
            self.assertIn("Secure", headers["Set-Cookie"])
            self.assertTrue(headers["Set-Cookie"].startswith("__Host-sharehub="))
            self.assertIn("보안 모드 · HTTPS".encode(), page)
            data = os.urandom(8 * 1024 * 1024)
            start = time.perf_counter()
            self.assertEqual(s.upload("encrypted.bin", data)[0], 201)
            status, _, downloaded = s.request("GET", "/download?path=encrypted.bin", headers={"Cookie": s.cookie})
            self.assertEqual(status, 200)
            self.assertEqual(downloaded, data)
            print(f"HTTPS loopback round trip: {len(data) * 2 / (time.perf_counter() - start) / 1048576:.1f} MiB/s (not a Wi-Fi benchmark)")
            untrusted = http.client.HTTPSConnection("127.0.0.1", s.port, timeout=5, context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT))
            try:
                with self.assertRaises(ssl.SSLCertVerificationError):
                    untrusted.request("GET", "/")
            finally:
                untrusted.close()
            with socket.create_connection(("127.0.0.1", s.port), timeout=5) as connection:
                connection.sendall(f"GET / HTTP/1.1\r\nHost: 127.0.0.1:{s.port}\r\n\r\n".encode())
                try:
                    response = connection.recv(1024)
                except ConnectionResetError:
                    response = b""
                self.assertNotIn(b"HTTP/1.1 200", response)
        finally:
            s.close()

    def test_11_secure_fail_closed(self):
        with tempfile.TemporaryDirectory(prefix="sharehub-no-cert-") as work:
            result = subprocess.run([str(EXECUTABLE), "--mode", "secure"], cwd=work, capture_output=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b"HTTPS certificate not configured", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
