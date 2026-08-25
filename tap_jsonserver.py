#!/usr/bin/env python3
"""
Network switch to allow network systems to communicate.

This tool is intended to allow emulated systems to communicate over ethernet protocols
without having to deal, themselves, with the tap configuration and distribution. It
allows multiple clients to connect and attached together, or to a given tap. This is
particularly useful when the rights to access the tap are only available to a priviledged
user - one you don't want to give the emulated system access to.

In the configuration where no tap is present, the clients which connect will communicate
with each other, but have no external effect.

In the configuration where the tap is present, the clients will be able to communicate
with whatever devices that tap is connected to - the host system, by default, but when
a bridge is installed, this will allow wider communications.


Transmission format
-------------------
The on-wire format for a frame is a line containing JSON-encoded data.
Each line should be a map containing the following fields:

    'frame_type':   The frame type, as an integer
    'src':          Source MAC address as a list of 6 integers.
    'dst':          Destination MAC address as a list of 6 integers.
    'data':         Data as base 64 encoded bytes.

Frames which are not recognised will be dropped.

This behaves as a MAC-learning Ethernet switch. Source MAC addresses are learned
per connected client, and per the TAP if one is configured. A frame addressed to a
known unicast MAC is delivered only to the client (or the TAP) that owns it; a
broadcast, multicast, or unknown-unicast frame is flooded to every other connected
client and to the TAP if configured. A MAC address already learned on one client
cannot be claimed by another client - the second client is disconnected instead. A
MAC learned via the TAP is not overridden by a client claiming it, and vice versa,
until the TAP-learned entry ages out from inactivity (--tap-mac-age) or the owning
client disconnects.


Setting up the TAP
------------------

On macOS, this seems to be partially achievable by:

    We use the tuntap driver - you will need this to be installed.

    Create a new bridge through the network configuration, using the interface you
    want to access the network from:

    * Go to Settings->Network.
    * Select the cog under the interfaces select 'Manage virtual interfaces'
    * Add an interface.
    * Give it an appropriate name (I chose 'Wifi Bridge')
    * Select the interface you want to bridge (eg the Wifi interface)
    * This will then tell you the BSD name of the bridge

    To get the data to be written to the tap, it is necessary to bring the tap interface up:

    * `ifconfig <tap interface> up`

    If you want to communicate with the outside world (not just with yourself), you will need
    to add the tap to the bridge:

    * `ifconfig bridge1 addm <tap interface>`

    It may be necessary to configure the system to forward packets:

    * `sysctl -w net.link.ether.inet.proxyall=1`
    * `sysctl -w net.inet.ip.forwarding=1`

    Even still, I couldn't get ICMP packets to make it all the way through the wifi interface.


On Linux you can set things up with:

    Create an interface which you will use for the communication:

    * `tunctl -t <tap name>`

    Create a bridge for your interfaces you will group together:

    * `brctl addbr br0`
    * `brctl addif br0 <bridged interface>`
    * `brctl addif br0 <tap interface>`
"""


import argparse
import os
import sys
from select import select

import base64
import fcntl
import json
import logging
import socket
import struct
import sys
import time
import queue


LOG = logging.getLogger('tap_jsonserver')

SELECT_TIMEOUT = 5.0  # seconds; poll granularity so select() wakes periodically
                      # to age out stale TAP-learned MAC entries even when idle.

# Unix domain socket for the CLI console, next to the script itself.
CLI_SOCKET_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'console0')

# Cisco-IOS-style syslog severity numbers, used only in the rendered message
# text ('%FACILITY-N-MNEMONIC: ...') - actual filtering still goes through
# Python's own logging levels/handlers.
_SEVERITY = {
    logging.DEBUG: 7,
    logging.INFO: 6,
    logging.WARNING: 4,
    logging.ERROR: 3,
    logging.CRITICAL: 2,
}


def log_event(level, facility, mnemonic, message, *args):
    """Emit a switch-style mnemonic log line, e.g. '%PORTSEC-4-MACCONFLICT: ...'.
    message/args follow %-style logging conventions so formatting is skipped
    entirely when `level` is below the configured threshold.

    Whether the leading '%' needs to be doubled depends on whether logging
    will run its own %-substitution pass at all: it only does so when args
    is non-empty (LogRecord.getMessage() skips it entirely for an empty
    args tuple), so an un-doubled '%' would otherwise reach the log verbatim.
    """
    tag = "%s-%d-%s: " % (facility, _SEVERITY[level], mnemonic)
    if args:
        LOG.log(level, "%%" + tag + message, *args)
    else:
        LOG.log(level, "%" + tag + message)


class Frame(object):

    def __init__(self, data, frame_type, src_mac, dst_mac):
        self.data = data
        self.frame_type = frame_type
        self.src_mac = src_mac
        self.dst_mac = dst_mac


class Client(object):
    """
    Client holds a client to whom we have connected - we exchange frames.
    """
    read_size = 1024 * 64
    max_pending = 1024 * 1024  # bytes buffered waiting for a '\n' before we give up
                               # on the client - a real frame line is a couple of KB.

    def __init__(self, socket):
        self.socket = socket
        self.name = socket.getpeername()
        self.socket_read = []

    def __repr__(self):
        return "<{}({})>".format(self.__class__.__name__,
                                 self.name)

    def pending_size(self):
        return sum(len(chunk) for chunk in self.socket_read)

    def frame_to_json(self, frame):
        send_data = {
                'frame_type': frame.frame_type,
                'src': frame.src_mac,
                'dst': frame.dst_mac,
                'data': base64.b64encode(frame.data).decode('ascii'),
            }
        return json.dumps(send_data)

    def json_to_frame(self, json_line):
        try:
            recv_data = json.loads(json_line)

            data = base64.b64decode(recv_data['data'])
            frame_type = recv_data['frame_type']

            src_mac = recv_data['src']
            if not isinstance(src_mac, list) or len(src_mac) != 6:
                raise ValueError("src address malformed (received %r)" % (src_mac,))

            dst_mac = recv_data['dst']
            if not isinstance(dst_mac, list) or len(dst_mac) != 6:
                raise ValueError("dst address malformed (received %r)" % (dst_mac,))

        except Exception:
            return None
        return Frame(data, frame_type, src_mac, dst_mac)

    def transmit(self, frame):
        if not self.socket:
            # A previous transmit in this batch already found the peer gone.
            return

        json_data = self.frame_to_json(frame)
        try:
            self.socket.sendall((json_data + "\n").encode('utf-8'))
        except OSError:
            # The peer disconnected between our last receive() and this
            # transmit() - tear down the same way receive() would.
            self.socket.close()
            self.socket = None

    def receive(self):
        """
        Return a list of frames or None if disconnected.
        """
        if not self.socket:
            # We're closed, so nothing to receive - report as disconnected.
            return None

        frames = []

        try:
            data = self.socket.recv(self.read_size)
        except socket.error:
            # Any socket error means that we're had a disconnect
            data = b''
        if not data:
            # No data means that we were disconnected, so we drop the connection
            self.socket.close()
            self.socket = None
            return None

        while b'\n' in data:
            (left, data) = data.split(b'\n', 1)
            self.socket_read.append(left)
            try:
                frame = self.json_to_frame(b''.join(self.socket_read).decode('utf-8'))
                if frame:
                    frames.append(frame)
            except Exception as exc:
                log_event(logging.WARNING, 'FRAME', 'BADFRAME', "Could not process frame: %s", exc)
                pass
            self.socket_read = []
        if data:
            self.socket_read.append(data)
            if self.pending_size() > self.max_pending:
                log_event(logging.WARNING, 'FRAME', 'OVERFLOW',
                          "Dropping %r: %i bytes buffered with no complete line (limit %i)",
                          self, self.pending_size(), self.max_pending)
                self.socket.close()
                self.socket = None
                return None

        return frames


class Server(object):

    def __init__(self, host='', port=33445):
        self.host = host
        self.port = port

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((self.host, self.port))
        self.socket.listen(5)

    def receive(self):
        """
        Receive from listening socket - we got a connection.

        There's apparently someone waiting on the socket, so we need to accept their connection
        """
        try:
            (conn, _) = self.socket.accept()
            # We got a connection - give them a client. Small, latency-sensitive
            # frames rather than bulk transfer, so disable Nagle's algorithm.
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            return Client(conn)
        except Exception as exc:
            log_event(logging.WARNING, 'SYS', 'ACCEPTFAIL', "accept() failed: %s", exc)
        return None


class CLIServer(object):
    """Listens on a Unix domain socket for the CLI console."""

    def __init__(self, path):
        self.path = path
        if os.path.exists(path):
            os.unlink(path)  # stale socket file from an unclean shutdown
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket.bind(path)
        self.socket.listen(5)

    def receive(self):
        try:
            (conn, _) = self.socket.accept()
            return CLISession(conn)
        except Exception as exc:
            log_event(logging.WARNING, 'SYS', 'CLIACCEPTFAIL', "CLI accept() failed: %s", exc)
        return None

    def close(self):
        self.socket.close()
        if os.path.exists(self.path):
            os.unlink(self.path)


class CLISession(object):
    """A connected CLI console client - plain line-buffered text, not the
    JSON frame protocol used by Client."""
    read_size = 4096
    max_pending = 64 * 1024  # a command line is short; this is just a safety cap

    def __init__(self, sock):
        self.socket = sock
        self.buffer = b''

    def __repr__(self):
        return "<CLISession(fd=%s)>" % (self.socket.fileno() if self.socket else 'closed',)

    def receive_lines(self):
        """Return a list of decoded command lines, or None if disconnected."""
        if not self.socket:
            return None
        try:
            data = self.socket.recv(self.read_size)
        except OSError:
            data = b''
        if not data:
            self.socket.close()
            self.socket = None
            return None

        self.buffer += data
        lines = []
        while b'\n' in self.buffer:
            (line, self.buffer) = self.buffer.split(b'\n', 1)
            lines.append(line.decode('utf-8', errors='replace').strip())
        if len(self.buffer) > self.max_pending:
            log_event(logging.WARNING, 'SYS', 'CLIOVERFLOW',
                      "Dropping %r: command line too long", self)
            self.socket.close()
            self.socket = None
            return None
        return lines

    def send(self, text):
        if not self.socket:
            return
        try:
            self.socket.sendall(text.encode('utf-8'))
        except OSError:
            # Same discipline as Client.transmit()/TAP.transmit(): never let
            # a dead peer's write failure escape into the main loop.
            self.socket.close()
            self.socket = None


class TAP(object):
    read_size = 1024 * 64

    # Linux constants
    TUNSETIFF = 0x400454ca
    IFF_TAP = 0x0002
    IFF_NO_PI = 0x1000


    def __init__(self, device='tap0'):
        # On macOS, `device` is a file path to the tap device itself; on
        # Linux it's the interface name to attach to via the shared
        # /dev/net/tun clone device (TUNSETIFF) - there's no per-interface
        # file to open directly.
        path = device if sys.platform == 'darwin' else '/dev/net/tun'
        self.socket = os.open(path, os.O_RDWR)
        if sys.platform != 'darwin':
            ifr = struct.pack('16sH', device.encode('utf-8'), self.IFF_TAP | self.IFF_NO_PI)
            fcntl.ioctl(self.socket, self.TUNSETIFF, ifr)
        self.name = device

    def __repr__(self):
        return "<{}({})>".format(self.__class__.__name__,
                                 self.name)

    def transmit(self, frame):
        src_mac = bytes(bytearray(frame.src_mac))
        dst_mac = bytes(bytearray(frame.dst_mac))
        frame_type = struct.pack('>H', frame.frame_type)
        packet = b''.join([dst_mac, src_mac, frame_type, frame.data])
        try:
            os.write(self.socket, packet)
        except OSError as exc:
            log_event(logging.WARNING, 'LINK', 'TAPWRITEFAIL',
                      "Failed to write to tap %r: %s (dropping this frame, tap stays up)", self, exc)

    def receive(self):
        frame = os.read(self.socket, self.read_size)

        # Framing format:
        # 6 bytes:  Destination MAC
        # 6 bytes:  Source MAC
        # 2 bytes:  Ethernet type (eg 0x800)
        # ...       Payload

        dst_mac = list(frame[0:6])
        src_mac = list(frame[6:12])
        (frame_type,) = struct.unpack('>H', frame[12:14])
        data = frame[14:]

        return [Frame(data, frame_type, src_mac, dst_mac)]


def format_mac(mac_tuple):
    """Render a MAC (tuple/list of 6 ints) as 'aa:bb:cc:dd:ee:ff' for logging."""
    return ':'.join('%02x' % (b,) for b in mac_tuple)


def purge_mac_table_for_port(mac_table, port):
    """Remove every mac_table entry owned by `port`. Called when a Client is torn down."""
    stale = [key for key, (owner, _expiry) in mac_table.items() if owner is port]
    for key in stale:
        del mac_table[key]


def age_mac_table(mac_table):
    """Expire TAP-owned entries whose aging deadline has passed. Client-owned
    entries have expiry None and are never touched here."""
    now = time.monotonic()
    expired = [key for key, (_owner, expiry) in mac_table.items()
               if expiry is not None and expiry <= now]
    for key in expired:
        log_event(logging.INFO, 'MAC', 'AGEOUT', "MAC %s aged out (TAP entry expired)", format_mac(key))
        del mac_table[key]


def learn_source(mac_table, sender_port, tap, src_mac, tap_mac_age):
    """
    Learn/refresh mac_table[tuple(src_mac)] for a frame arriving on sender_port
    (a Client instance, or the TAP instance).

    Returns:
      'ok'       - learned/refreshed; caller should queue the frame.
      'drop'     - frame must be dropped, no state changed. Covers a client-
                   or TAP-owned MAC being claimed from the other side of that
                   boundary - client<->TAP mismatches are always rejected, not
                   relearned.
      'conflict' - a second, different client claimed a MAC already owned by
                   another client; caller must drop the frame AND disconnect
                   sender_port (the new/duplicate client) - this is the only
                   case ownership can move without a prior disconnect or
                   aging expiry.
    """
    key = tuple(src_mac)
    is_tap_sender = sender_port is tap
    entry = mac_table.get(key)

    if entry is None:
        expiry = time.monotonic() + tap_mac_age if is_tap_sender else None
        mac_table[key] = (sender_port, expiry)
        return 'ok'

    owner, _expiry = entry

    if owner is sender_port:
        if is_tap_sender:
            mac_table[key] = (owner, time.monotonic() + tap_mac_age)
        return 'ok'

    owner_is_tap = owner is tap

    if owner_is_tap or is_tap_sender:
        # A client<->TAP mismatch in either direction: never let the new
        # sender pre-empt the existing owner. The entry only changes once
        # it ages out (TAP-owned) or the owning client disconnects.
        log_event(logging.WARNING, 'PORTSEC', 'BOUNDARY',
                  "MAC %s owned by %r, also seen from %r", format_mac(key), owner, sender_port)
        return 'drop'

    # Both owner and sender are (different) clients - real port-security conflict.
    log_event(logging.WARNING, 'PORTSEC', 'MACCONFLICT',
              "MAC %s already owned by client %r, also claimed by %r", format_mac(key), owner, sender_port)
    return 'conflict'


def resolve_targets(mac_table, dst_mac, ports, sender_port):
    """Return the ports a frame with this dst_mac should be sent to (never
    including sender_port)."""
    if dst_mac[0] & 0x01:
        # I/G bit set: broadcast or multicast - flood to everyone but the sender.
        return [port for port in ports if port is not sender_port]

    owner, _expiry = mac_table.get(tuple(dst_mac), (None, None))
    if owner is None:
        return [port for port in ports if port is not sender_port]  # unknown unicast
    if owner is sender_port:
        return []  # never reflect to sender
    return [owner]


def cli_show_interfaces(arg, clients, tap, mac_table, rlist):
    lines = ["Port  Type    Peer"]
    for client in clients.values():
        if client.socket:
            lines.append("%-5s %-7s %s" % (client.socket.fileno(), "client", client.name))
    if tap:
        lines.append("%-5s %-7s %s" % (tap.socket, "tap", tap.name))
    if not clients and not tap:
        lines.append("(none)")
    return "\n".join(lines)


def cli_show_mac_address_table(arg, clients, tap, mac_table, rlist):
    lines = ["Mac Address         Type    Port    Age"]
    now = time.monotonic()
    for mac, (owner, expiry) in sorted(mac_table.items()):
        kind = "tap" if owner is tap else "client"
        owner_port = owner.socket if kind == "tap" else (owner.socket.fileno() if owner.socket else "-")
        age = "%ds" % (max(0, int(expiry - now)),) if expiry is not None else "-"
        lines.append("%-19s %-7s %-7s %s" % (format_mac(mac), kind, owner_port, age))
    if not mac_table:
        lines.append("(empty)")
    return "\n".join(lines)


def cli_clear_mac_address_table(arg, clients, tap, mac_table, rlist):
    count = len(mac_table)
    mac_table.clear()
    log_event(logging.INFO, 'MAC', 'CLEARED', "MAC address table cleared via CLI (%d entries)", count)
    return "Cleared %d entries" % (count,)


def cli_clear_interface(arg, clients, tap, mac_table, rlist):
    try:
        port = int(arg)
    except ValueError:
        return "%% Invalid interface port: %r" % (arg,)
    for sock, client in list(clients.items()):
        if client.socket and client.socket.fileno() == port:
            log_event(logging.WARNING, 'LINK', 'CLICLEAR', "Client %r disconnected via CLI", client)
            client.socket.close()
            client.socket = None
            purge_mac_table_for_port(mac_table, client)
            del clients[sock]
            rlist.remove(sock)
            return "Cleared interface %d" % (port,)
    return "%% No such interface: port %d" % (port,)


def cli_show_logging(arg, clients, tap, mac_table, rlist):
    return "Current logging level: %s" % (logging.getLevelName(logging.getLogger().level),)


def cli_set_logging_level(arg, clients, tap, mac_table, rlist):
    level_name = arg.upper()
    if level_name not in ('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'):
        return "%% Invalid level: %r" % (arg,)
    logging.getLogger().setLevel(getattr(logging, level_name))
    log_event(logging.INFO, 'SYS', 'LOGLEVEL', "Logging level changed to %s via CLI", level_name)
    return "Logging level set to %s" % (level_name,)


def cli_help(arg, clients, tap, mac_table, rlist):
    return "\n".join(' '.join(words) + (" <%s>" % arg_name if arg_name else "")
                     for words, arg_name, _handler in CLI_COMMANDS)


def cli_exit(arg, clients, tap, mac_table, rlist):
    return None


CLI_COMMANDS = [
    (('show', 'interfaces', 'status'), None, cli_show_interfaces),
    (('show', 'mac', 'address-table'), None, cli_show_mac_address_table),
    (('show', 'logging'), None, cli_show_logging),
    (('clear', 'mac', 'address-table'), None, cli_clear_mac_address_table),
    (('clear', 'interface'), 'port', cli_clear_interface),
    (('logging', 'level'), 'level', cli_set_logging_level),
    (('help',), None, cli_help),
    (('?',), None, cli_help),
    (('exit',), None, cli_exit),
]


def resolve_cli_command(tokens):
    """Cisco-style progressive prefix matching over CLI_COMMANDS.
    Returns (handler, arg) on success, or a '%...' error string."""
    candidates = CLI_COMMANDS
    for i, token in enumerate(tokens):
        token = token.lower()
        candidates = [c for c in candidates if len(c[0]) > i and c[0][i].startswith(token)]
        if not candidates:
            return "%% Unknown command: %r" % (token,)
        exact = [c for c in candidates if len(c[0]) == i + 1]
        if len(exact) == 1 and len(candidates) == 1:
            words, arg_name, handler = exact[0]
            remaining = tokens[i + 1:]
            if arg_name and len(remaining) != 1:
                return "%% Command %r requires a <%s> argument" % (' '.join(words), arg_name)
            if not arg_name and remaining:
                return "%% Unknown command: %r" % (' '.join(remaining),)
            return (handler, remaining[0] if arg_name else None)
    if len(candidates) > 1:
        return "% Ambiguous command."
    # Exactly one candidate survived, even though it may have literal words
    # beyond what was typed (e.g. "show mac" for "show mac address-table") -
    # unambiguous, so auto-complete it rather than demanding the rest.
    words, arg_name, handler = candidates[0]
    if arg_name:
        return "%% Command %r requires a <%s> argument" % (' '.join(words), arg_name)
    return (handler, None)


def setup_argparse():
    parser = argparse.ArgumentParser(usage="%s [<options>]" % (os.path.basename(sys.argv[0]),),
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('--port', type=int, action='store', default=33445,
                        help="Port to listen for connections on")
    parser.add_argument('--tap-device', action='store', default=None,
                        help="Tap device to attach to: a file path on macOS, "
                             "an interface name on Linux. Supplying this enables "
                             "the tap; omit it to run without one")
    parser.add_argument('--tap-mac-age', type=float, action='store', default=300.0,
                        help="Seconds of inactivity before a MAC address learned via "
                             "the tap is aged out of the switch's MAC table")
    parser.add_argument('--log-level', action='store', default='INFO',
                        choices=('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'),
                        help="Logging verbosity")
    return parser


def main():
    parser = setup_argparse()
    options = parser.parse_args()

    logging.basicConfig(level=getattr(logging, options.log_level), format='%(asctime)s %(message)s')

    server = Server(port=options.port)
    if options.tap_device:
        tap = TAP(device=options.tap_device)
    else:
        tap = None
    cli_server = CLIServer(CLI_SOCKET_PATH)

    clients = {}
    cli_sessions = {}
    mac_table = {}
    rlist = [server.socket, cli_server.socket]
    if tap:
        rlist.append(tap.socket)

    queued_frames = queue.Queue()

    try:
        log_event(logging.INFO, 'SYS', 'START', "Awaiting connections and packets")
        while True:
            (ready, _, _) = select(rlist, [], [], SELECT_TIMEOUT)
            age_mac_table(mac_table)
            for socket in ready:
                if tap and socket == tap.socket:
                    frames = tap.receive()
                    if frames:
                        for frame in frames:
                            if learn_source(mac_table, tap, tap, frame.src_mac, options.tap_mac_age) == 'ok':
                                queued_frames.put((tap, frame))


                elif socket == server.socket:
                    client = server.receive()
                    if client:
                        log_event(logging.INFO, 'LINK', 'CLIENTUP', "Client %r connected", client)
                        clients[client.socket] = client
                        rlist.append(client.socket)

                elif socket == cli_server.socket:
                    session = cli_server.receive()
                    if session:
                        log_event(logging.INFO, 'LINK', 'CLIUP', "CLI session %r connected", session)
                        cli_sessions[session.socket] = session
                        rlist.append(session.socket)
                        session.send("% ")

                elif socket in cli_sessions:
                    session = cli_sessions[socket]
                    lines = session.receive_lines()
                    if lines is None:
                        log_event(logging.INFO, 'LINK', 'CLIDOWN', "CLI session %r disconnected", session)
                        del cli_sessions[socket]
                        rlist.remove(socket)
                    else:
                        for line in lines:
                            if not line:
                                continue
                            try:
                                result = resolve_cli_command(line.split())
                                if isinstance(result, str):
                                    session.send(result + "\n% ")
                                    continue
                                handler, arg = result
                                output = handler(arg, clients, tap, mac_table, rlist)
                            except Exception as exc:
                                # A bug in a CLI handler must never take the
                                # switch down with it - same discipline as
                                # the transmit() guards elsewhere.
                                log_event(logging.ERROR, 'SYS', 'CLIERROR',
                                          "CLI command %r raised %s: %s",
                                          line, type(exc).__name__, exc)
                                session.send("% Internal error processing command\n% ")
                                continue
                            if output is None:
                                log_event(logging.INFO, 'LINK', 'CLIDOWN',
                                          "CLI session %r disconnected", session)
                                if session.socket:
                                    session.socket.close()
                                    session.socket = None
                                del cli_sessions[socket]
                                rlist.remove(socket)
                                break
                            session.send(output + "\n% ")

                elif socket in clients:
                    client = clients[socket]
                    frames = client.receive()
                    if frames is None:
                        # They disconnected, remove from our list
                        log_event(logging.INFO, 'LINK', 'CLIENTDOWN', "Client %r disconnected", client)
                        purge_mac_table_for_port(mac_table, client)
                        del clients[socket]
                        rlist.remove(socket)
                    else:
                        for frame in frames:
                            status = learn_source(mac_table, client, tap, frame.src_mac, options.tap_mac_age)
                            if status == 'conflict':
                                log_event(logging.WARNING, 'PORTSEC', 'KICK',
                                          "Disconnected client %r (duplicate MAC)", client)
                                client.socket.close()
                                client.socket = None
                                purge_mac_table_for_port(mac_table, client)
                                del clients[socket]
                                rlist.remove(socket)
                                break
                            elif status == 'ok':
                                queued_frames.put((client, frame))

                # Let's try sending the frames to all the clients
                if not queued_frames.empty():
                    ports = list(clients.values())
                    if tap:
                        ports.append(tap)

                    while True:
                        try:
                            (receiver_port, frame) = queued_frames.get_nowait()
                            log_event(logging.DEBUG, 'FRAME', 'DISTRIB', "type &%04x (%i bytes) from %r",
                                      frame.frame_type, len(frame.data), receiver_port)
                            for port in resolve_targets(mac_table, frame.dst_mac, ports, receiver_port):
                                log_event(logging.DEBUG, 'FRAME', 'TX', "to port %r", port)
                                port.transmit(frame)
                        except queue.Empty:
                            break

                    # A transmit() above may have discovered a dead client;
                    # drop it the same way a failed receive() would.
                    for stale_socket, stale_client in list(clients.items()):
                        if not stale_client.socket:
                            log_event(logging.INFO, 'LINK', 'CLIENTDOWN', "Client %r disconnected", stale_client)
                            purge_mac_table_for_port(mac_table, stale_client)
                            del clients[stale_socket]
                            rlist.remove(stale_socket)

    except KeyboardInterrupt:
        log_event(logging.INFO, 'SYS', 'SHUTDOWN', "Switch terminated.")
    finally:
        cli_server.close()


if __name__ == '__main__':
    sys.exit(main())
