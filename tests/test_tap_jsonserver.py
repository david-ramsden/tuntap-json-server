import json
import os
import select
import socket
import subprocess
import sys
import time
import unittest


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVER = os.path.join(ROOT, "tap_jsonserver.py")


class JsonServerTest(unittest.TestCase):
    def setUp(self):
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()

        self.clients = []
        self.server = subprocess.Popen(
            [sys.executable, "-u", SERVER, "--port", str(port)],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )

        try:
            for _ in range(2):
                self.clients.append(self._connect(port))
            self._wait_for_connections(2)
        except Exception:
            for client in self.clients:
                client.close()
            self._stop_server()
            raise

    def tearDown(self):
        for client in self.clients:
            client.close()
        self._stop_server()

    def _connect(self, port):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                client = socket.create_connection(("127.0.0.1", port), timeout=1)
                client.settimeout(2)
                return client
            except OSError:
                if self.server.poll() is not None:
                    break
                time.sleep(0.05)

        self.fail("JSON server did not accept connections")

    def _wait_for_connections(self, expected):
        deadline = time.monotonic() + 5
        output = b""

        while output.count(b"Got a client") < expected and time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            ready, _, _ = select.select([self.server.stdout], [], [], remaining)
            if not ready:
                break

            data = os.read(self.server.stdout.fileno(), 4096)
            if not data:
                break
            output += data

        if output.count(b"Got a client") != expected:
            decoded = output.decode("utf-8", errors="replace")
            self.fail("Server did not register both clients:\n{}".format(decoded))

    def _stop_server(self):
        if self.server.poll() is None:
            self.server.terminate()
            try:
                self.server.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.server.kill()
                self.server.wait(timeout=2)
        if self.server.stdout:
            self.server.stdout.close()

    def test_forwards_a_json_frame_to_another_client(self):
        frame = {
            "frame_type": 0x0800,
            "src": [2, 0, 0, 0, 0, 1],
            "dst": [2, 0, 0, 0, 0, 2],
            "data": "SGVsbG8sIFJJU0MgT1Mh",
        }
        encoded = (json.dumps(frame) + "\n").encode("utf-8")

        self.clients[0].sendall(encoded)

        received = b""
        while b"\n" not in received:
            chunk = self.clients[1].recv(4096)
            self.assertTrue(chunk, "Server closed the receiving connection")
            received += chunk
        forwarded = json.loads(received.split(b"\n", 1)[0].decode("utf-8"))
        self.assertEqual(forwarded, frame)


if __name__ == "__main__":
    unittest.main()
