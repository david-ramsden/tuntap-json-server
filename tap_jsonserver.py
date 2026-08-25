#!/usr/bin/env python3
"""
Network HUB to allow network systems to communcate.

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
Each frame received will be replicated yo all the connected clients, and to the TAP if
one is configured.


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
import socket
import struct
import sys
import queue


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

    def __init__(self, socket):
        self.socket = socket
        self.name = socket.getpeername()
        self.socket_read = []

    def __repr__(self):
        return "<{}({})>".format(self.__class__.__name__,
                                 self.name)

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
                print("Could not process frame: %s" % (exc,))
                pass
            self.socket_read = []
        if data:
            self.socket_read.append(data)

        return frames


class Server(object):

    def __init__(self, host='', port=33445):
        self.host = host
        self.port = port

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((self.host, self.port))
        self.socket.listen(1)

    def receive(self):
        """
        Receive from listening socket - we got a connection.

        There's apparently someone waiting on the socket, so we need to accept their connection
        """
        try:
            (socket, _) = self.socket.accept()
            # We got a connection - give them a client.
            return Client(socket)
        except Exception as exc:
            print("Nobody's really there?!")
            pass
        return None


class TAP(object):
    read_size = 1024 * 64

    # Linux constants
    TUNSETIFF = 0x400454ca
    TUNSETOWNER = TUNSETIFF + 2
    IFF_TUN = 0x0001
    IFF_TAP = 0x0002
    IFF_NO_PI = 0x1000


    def __init__(self, filename='/dev/tap0', device='tap0'):
        if sys.platform == 'darwin':
            self.socket = os.open(filename, os.O_RDWR)
            self.name = 'filename'
        else:
            self.socket = os.open('/dev/net/tun', os.O_RDWR)
            ifr = struct.pack('16sH', device.encode('utf-8'), self.IFF_TAP | self.IFF_NO_PI)
            fcntl.ioctl(self.socket, self.TUNSETIFF, ifr)
            #fcntl.ioctl(self.socket, self.TUNSETOWNER, 1000)
            self.name = device

    def __repr__(self):
        return "<{}({})>".format(self.__class__.__name__,
                                 self.name)

    def transmit(self, frame):
        src_mac = bytes(bytearray(frame.src_mac))
        dst_mac = bytes(bytearray(frame.dst_mac))
        frame_type = struct.pack('>H', frame.frame_type)
        packet = b''.join([dst_mac, src_mac, frame_type, frame.data])
        os.write(self.socket, packet)

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


def setup_argparse():
    parser = argparse.ArgumentParser(usage="%s [<options>]" % (os.path.basename(sys.argv[0]),),
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('--port', type=int, action='store', default=33445,
                        help="Port to listen for connections on")
    parser.add_argument('--tap-enable', action='store_true',
                        help="Enable use of the tap")
    parser.add_argument('--tap-filename', action='store', default='/dev/tap0',
                        help="Tap filename to connect to (on macOS)")
    parser.add_argument('--tap-device', action='store', default='tap0',
                        help="Tap device to connect to (on Linux)")
    return parser


def main():
    parser = setup_argparse()
    options = parser.parse_args()

    server = Server(port=options.port)
    if options.tap_enable:
        tap = TAP()
    else:
        tap = None

    clients = {}
    rlist = [server.socket]
    if tap:
        rlist.append(tap.socket)

    queued_frames = queue.Queue()

    try:
        print("Awaiting connections and packets")
        while True:
            (ready, _, _) = select(rlist,[],[])
            #if ready:
            #    print("Ready sockets: %r" % (ready,))
            for socket in ready:
                if tap and socket == tap.socket:
                    frames = tap.receive()
                    if frames:
                        for frame in frames:
                            queued_frames.put((tap, frame))


                elif socket == server.socket:
                    client = server.receive()
                    if client:
                        print("Got a client %r" % (client,))
                        clients[client.socket] = client
                        rlist.append(client.socket)

                elif socket in clients:
                    client = clients[socket]
                    frames = client.receive()
                    if frames is None:
                        # They disconnected, remove from our list
                        print("Disconnected client %r" % (client,))
                        del clients[socket]
                        rlist.remove(socket)
                    else:
                        for frame in frames:
                            queued_frames.put((client, frame))

                # Let's try sending the frames to all the clients
                if not queued_frames.empty():
                    ports = list(clients.values())
                    if tap:
                        ports.append(tap)

                    while True:
                        try:
                            (receiver_port, frame) = queued_frames.get_nowait()
                            print("Distributing frame type &%04x (%i bytes) from %r" % (frame.frame_type,
                                                                                        len(frame.data),
                                                                                        receiver_port,))
                            for port in ports:
                                if port == receiver_port:
                                    # Never reflect frames to their sender
                                    continue
                                print("Transmit to port %r" % (port,))
                                port.transmit(frame)
                        except queue.Empty:
                            break

                    # A transmit() above may have discovered a dead client;
                    # drop it the same way a failed receive() would.
                    for stale_socket, stale_client in list(clients.items()):
                        if not stale_client.socket:
                            print("Disconnected client %r" % (stale_client,))
                            del clients[stale_socket]
                            rlist.remove(stale_socket)

    except KeyboardInterrupt:
        print("HUB terminated.")


if __name__ == '__main__':
    sys.exit(main())
