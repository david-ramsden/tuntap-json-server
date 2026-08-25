# Tun-Tap JSON Server

This tool provides a means by which emulators may communicate with one another over a virtual network. The intended use is that the emulators which need to transmit ethernet frames do so through the server. This lets them communicate with other emulator systems connected to the same server.
The server may be connected to a 'tap' interface, which allows it to communicate with other systems on the same network.

Providing a connection to a network in this manner allows the emulator to run without any privileges, whilst the network communication is left to a separate process.

## Communications

The TCP server listens on port 33445 by default, awaiting connections from clients. It communicates ethernet frames encoded in JSON lines. Each line is a JSON encoded map containing the following fields:

* `frame_type`:   The frame type, as an integer
* `src`:          Source MAC address as a list of 6 integers.
* `dst`:          Destination MAC address as a list of 6 integers.
* `data`:         Data as base 64 encoded bytes.

The server behaves as a MAC-learning Ethernet switch. Source MAC addresses are learned per connected client, and per the tap if one is configured:

* A frame addressed to a known unicast MAC is delivered only to the client (or the tap) that owns it.
* Broadcast, multicast, and frames addressed to an unknown MAC are flooded to every other connected client, and to the tap if configured.
* A MAC address already learned on one client cannot be claimed by another client - the second client is disconnected instead.
* A MAC address learned via the tap is not overridden by a client claiming it, and vice versa, until the tap-learned entry ages out from inactivity (`--tap-mac-age`, default 300 seconds) or the owning client disconnects.


## Usage

When no external connection is required, a tap is unnecessary and the service can be run on any system:

    ./tap_jsonserver.py --port <port number>

## Console

Every run of the switch opens a CLI console on a Unix domain socket called `console0`, next to the script itself. Connect to it locally with `socat` or `nc`:

    socat - UNIX-CONNECT:console0

Commands support Cisco-style partial matching, including matching a whole command when the words given are unambiguous even if incomplete (e.g. `sh int` or just `show mac` both work):

* `show interfaces status` - lists connected clients and the tap (if configured), each with a port number.
* `show mac address-table` - lists learned MAC addresses, their owning port (matching `show interfaces status`), and (for tap-learned entries) time until they age out.
* `clear mac address-table` - forgets all learned MAC addresses. This only affects switching decisions (traffic floods until relearned, which happens automatically on the next frame from each source) - it does not disconnect anyone.
* `clear interface <port>` - disconnects the client with that port (from `show interfaces status`).
* `show logging` / `logging level <LEVEL>` - reads or changes the logging verbosity while running.
* `help` (or `?`) - lists the available commands.
* `exit` - closes the console session.

