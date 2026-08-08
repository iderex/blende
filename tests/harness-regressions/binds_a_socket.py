# guard: binds-a-socket
"""A sample that binds a socket on loopback, so the guard has to refuse it.

Loopback rather than an outward address, because loopback is the one a
contributor reaches for when a test needs a server and the one that looks
harmless. Issue #12 forbids it anyway: on a Windows host a bind raises a
firewall dialog only an administrator can answer, and a suite that stops to
ask a question is a suite that stops running.

Port zero, so that if the guard ever fails to bite the sample takes a port the
operating system chose rather than one something else is already using.
"""

from __future__ import annotations

import socket

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
    listener.bind(("127.0.0.1", 0))
