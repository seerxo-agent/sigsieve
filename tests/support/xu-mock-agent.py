#!/usr/bin/env python3
"""Minimal SSH agent for the F-46 cross-user test (tests/cross_user.rs).

Usage: xu-mock-agent.py SOCKET LOG

Listens on SOCKET and appends the message type of every request it
receives to LOG, one per line, so the test can prove that nothing reached
it. Identity requests get an empty list; everything else gets FAILURE.
It holds no keys and never signs. Unlike OpenSSH's ssh-agent it does not
check its client's uid, so it stands in for an agent that would serve
anyone: refusing it is SigSieve's job alone.
"""

import os
import socket
import struct
import sys

IDENTITIES_ANSWER = bytes([12]) + struct.pack(">I", 0)
FAILURE = bytes([5])


def recv_exact(conn, n):
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def serve(conn, log):
    while True:
        head = recv_exact(conn, 4)
        if head is None:
            return
        (length,) = struct.unpack(">I", head)
        if length == 0 or length > 256 * 1024:
            return
        body = recv_exact(conn, length)
        if body is None:
            return
        log.write(f"{body[0]}\n")
        log.flush()
        reply = IDENTITIES_ANSWER if body[0] == 11 else FAILURE
        conn.sendall(struct.pack(">I", len(reply)) + reply)


def main():
    path, log_path = sys.argv[1], sys.argv[2]
    with open(log_path, "a", encoding="ascii") as log:
        # The test, possibly running as another user, reads the log.
        os.chmod(log_path, 0o644)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(path)
        listener.listen(8)
        while True:
            conn, _ = listener.accept()
            with conn:
                serve(conn, log)


if __name__ == "__main__":
    main()
