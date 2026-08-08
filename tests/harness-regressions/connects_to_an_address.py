# guard: reaches-the-network
"""A sample that connects to a literal address without resolving anything.

One of two samples for this guard, and they are two because the guard refuses
at two places. This one has to reach the connection rather than the name
lookup, so it calls `connect` on a socket it made itself. The obvious spelling
does not work: `socket.create_connection` asks the resolver even for an
address that is already numeric, so a sample written that way is refused by
the name-resolution arm and proves nothing about the other one. Measured by
deleting the connection arm and watching this sample stay refused.

The address is from the range RFC 5737 reserves for documentation, and the
timeout is short, so a run where the guard failed to bite ends rather than
waiting on an address that will never answer.
"""

import socket

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
    client.settimeout(0.1)
    client.connect(("192.0.2.1", 80))
