#!/usr/bin/env python3
"""Exercise the deployed proxy policy with disposable local HTTP backends.
Requires Python 3, openssl, and a TLS-enabled HAProxy binary. No provider calls.
"""
import argparse
import http.client
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def wait_for(predicate):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.05)
    raise AssertionError('proxy readiness deadline exceeded')


class Backend(ThreadingHTTPServer):
    daemon_threads = True
    def __init__(self, truncate):
        super().__init__(('127.0.0.1', 0), Handler)
        self.truncate = truncate
        self.ready = True
        self.checks = 0
        self.posts = 0
        self.lock = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def log_message(self, *_):
        pass

    def do_GET(self):
        with self.server.lock:
            ready = self.server.ready
            self.server.checks += 1
        self.send_response(200 if ready else 503)
        self.send_header('Content-Length', '0')
        self.end_headers()

    def do_POST(self):
        self.rfile.read(int(self.headers.get('Content-Length', '0')))
        with self.server.lock:
            self.server.posts += 1
        if self.server.truncate == 'headers':
            self.close_connection = True
            return
        self.send_response(200)
        self.send_header('Transfer-Encoding', 'chunked')
        self.end_headers()
        self.wfile.write(b'5\r\nhello\r\n')
        if not self.server.truncate:
            self.wfile.write(b'0\r\n\r\n')
        self.wfile.flush()
        self.close_connection = True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--haproxy', required=True)
    args = parser.parse_args()
    first, standby = Backend(True), Backend(False)
    for backend in (first, standby):
        threading.Thread(target=backend.serve_forever, daemon=True).start()
    process = None
    try:
        with tempfile.TemporaryDirectory(prefix='hypgate-proxy-') as directory:
            root = Path(directory)
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                '-subj', '/CN=localhost', '-days', '1', '-keyout', str(root/'key.pem'),
                '-out', str(root/'cert.pem')], check=True, capture_output=True)
            pem = root/'tls.pem'
            pem.write_bytes((root/'cert.pem').read_bytes() + (root/'key.pem').read_bytes())
            pem.chmod(0o600)
            listen = port()
            config = (Path(__file__).resolve().parents[1]/'deploy/haproxy.cfg').read_text()
            config = config.replace(':8443 ssl', f'127.0.0.1:{listen} ssl')
            config = config.replace('${HYPGATE_TLS_PEM}', str(pem))
            config = config.replace('127.0.0.1:8081', f'127.0.0.1:{first.server_port}')
            config = config.replace('127.0.0.1:8082', f'127.0.0.1:{standby.server_port}')
            path = root/'haproxy.cfg'
            path.write_text(config)
            subprocess.run([args.haproxy, '-c', '-f', str(path)], check=True)
            with (root/'proxy.log').open('wb') as output:
                process = subprocess.Popen([args.haproxy, '-db', '-f', str(path)], stdout=output, stderr=output)
                wait_for(lambda: first.checks >= 3 and standby.checks >= 3)
                context = ssl.create_default_context(cafile=str(root/'cert.pem'))
                def request(method, path):
                    connection = http.client.HTTPSConnection('localhost', listen, context=context, timeout=5)
                    connection.request(method, path, body=b'')
                    return connection, connection.getresponse()
                connection, response = request('POST', '/routes/7')
                assert response.status == 200
                try:
                    response.read()
                    raise AssertionError('truncated generation became successful EOF')
                except http.client.IncompleteRead:
                    pass
                finally:
                    connection.close()
                assert first.posts == 1 and standby.posts == 0, 'generation replayed'
                first.truncate = 'headers'
                connection, response = request('POST', '/routes/7')
                assert response.status in (502, 503), response.status
                response.read()
                connection.close()
                assert first.posts == 2 and standby.posts == 0, 'pre-header failure replayed'
                with first.lock:
                    first.ready = False
                    baseline = first.checks
                wait_for(lambda: first.checks >= baseline + 3)
                connection, response = request('POST', '/routes/7')
                assert response.status == 200 and response.read() == b'hello'
                connection.close()
                assert first.posts == 2 and standby.posts == 1
                connection, response = request('GET', '/metrics')
                assert response.status == 404
                response.read()
                connection.close()
                print('PASS: pre/post-header failures not replayed; new request uses ready standby; metrics not public')
    finally:
        if process is not None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        for backend in (first, standby):
            backend.shutdown()
            backend.server_close()


if __name__ == '__main__':
    main()
