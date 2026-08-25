import base64
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


class ServerTestCase(unittest.TestCase):
    """Shared subprocess-server lifecycle helpers for the tests below."""

    def _start_server(self, *extra_args):
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()

        self.clients = []
        self.server = subprocess.Popen(
            [sys.executable, "-u", SERVER, "--port", str(port)] + list(extra_args),
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        return port

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

        while output.count(b"CLIENTUP") < expected and time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            ready, _, _ = select.select([self.server.stdout], [], [], remaining)
            if not ready:
                break

            data = os.read(self.server.stdout.fileno(), 4096)
            if not data:
                break
            output += data

        if output.count(b"CLIENTUP") != expected:
            decoded = output.decode("utf-8", errors="replace")
            self.fail("Server did not register all clients:\n{}".format(decoded))

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


class JsonServerTest(ServerTestCase):
    def setUp(self):
        port = self._start_server()
        try:
            for _ in range(2):
                self.clients.append(self._connect(port))
            self._wait_for_connections(2)
        except Exception:
            for client in self.clients:
                client.close()
            self._stop_server()
            raise

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


class SwitchingTest(ServerTestCase):
    """MAC-learning switch behaviour: known-unicast is delivered only to its
    owning port, and a duplicate source MAC from a second client gets that
    second (not the original) client disconnected."""

    def setUp(self):
        port = self._start_server()
        try:
            for _ in range(3):
                self.clients.append(self._connect(port))
            self._wait_for_connections(3)
        except Exception:
            for client in self.clients:
                client.close()
            self._stop_server()
            raise

    def _send_frame(self, client, src, dst, payload=b"hello"):
        frame = {
            "frame_type": 0x0800,
            "src": src,
            "dst": dst,
            "data": base64.b64encode(payload).decode("ascii"),
        }
        client.sendall((json.dumps(frame) + "\n").encode("utf-8"))

    def _recv_frame(self, client):
        received = b""
        while b"\n" not in received:
            chunk = client.recv(4096)
            self.assertTrue(chunk, "Server closed the receiving connection")
            received += chunk
        return json.loads(received.split(b"\n", 1)[0].decode("utf-8"))

    def _assert_nothing_received(self, client, timeout=0.5):
        client.settimeout(timeout)
        try:
            data = client.recv(4096)
        except socket.timeout:
            return
        finally:
            client.settimeout(2)
        self.assertEqual(data, b"", "Unexpectedly received data: %r" % (data,))

    def test_known_unicast_is_not_flooded(self):
        client_a, client_b, client_c = self.clients
        mac_a = [2, 0, 0, 0, 0, 0xA]
        mac_b = [2, 0, 0, 0, 0, 0xB]
        broadcast = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]

        # A's MAC isn't known yet, so this floods - that also learns it.
        self._send_frame(client_a, mac_a, broadcast)
        self._recv_frame(client_b)
        self._recv_frame(client_c)

        # B sends a unicast frame to A's now-known MAC.
        self._send_frame(client_b, mac_b, mac_a)
        forwarded = self._recv_frame(client_a)
        self.assertEqual(forwarded["src"], mac_b)
        self.assertEqual(forwarded["dst"], mac_a)

        # C is uninvolved and must not have received it.
        self._assert_nothing_received(client_c)

    def test_duplicate_mac_disconnects_the_new_client(self):
        client_a, client_b, client_c = self.clients
        mac = [2, 0, 0, 0, 0, 0xA]
        broadcast = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]

        # A claims the MAC first.
        self._send_frame(client_a, mac, broadcast)
        self._recv_frame(client_b)
        self._recv_frame(client_c)

        # B claims the same source MAC - the switch must disconnect B, not A.
        self._send_frame(client_b, mac, broadcast)
        client_b.settimeout(5)
        self.assertEqual(client_b.recv(4096), b"",
                         "Duplicate-MAC client was not disconnected")

        # A must still be usable.
        self._send_frame(client_a, mac, broadcast)
        forwarded = self._recv_frame(client_c)
        self.assertEqual(forwarded["src"], mac)


class BufferingLimitTest(ServerTestCase):
    """A client which never sends a newline must be dropped, not allowed to
    buffer unbounded memory."""

    def setUp(self):
        port = self._start_server()
        try:
            self.clients.append(self._connect(port))
            self._wait_for_connections(1)
        except Exception:
            for client in self.clients:
                client.close()
            self._stop_server()
            raise

    def test_client_with_no_newline_is_dropped_once_over_the_limit(self):
        client = self.clients[0]
        junk = b"A" * 65536  # comfortably over Client.max_pending (1MB) after a few sends

        dropped = False
        try:
            for _ in range(64):  # 4MB total
                client.sendall(junk)
        except OSError:
            dropped = True

        if not dropped:
            client.settimeout(5)
            self.assertEqual(client.recv(4096), b"",
                             "Server went on buffering a line which never ends")

        self.assertIsNone(self.server.poll(), "Server process died")


if __name__ == "__main__":
    unittest.main()
