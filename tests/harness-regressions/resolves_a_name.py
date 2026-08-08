# guard: reaches-the-network
"""A sample that resolves a name, which is the other half of the same guard.

The second of the two samples for `reaches-the-network`. A test that only
looks a name up has already left the host, and a guard written against the
connection alone would let it through and then be credited with covering the
network.

The name is in the `.invalid` top-level domain, which RFC 2606 reserves and
guarantees will never be delegated, so a run where the guard failed to bite
asks a resolver a question that has one answer everywhere.
"""

import socket

socket.getaddrinfo("authority.invalid", 80)
