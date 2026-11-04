"""A minimal SMTP server that keeps received messages in memory.

Shared by the reference probes and the public contracts. It speaks plain SMTP
(no TLS, no authentication) on a loopback port and records each message's
envelope and raw content.
"""

import email
import email.policy
import socket
import socketserver
import threading


class _Handler(socketserver.StreamRequestHandler):
    def reply(self, line):
        self.wfile.write(line.encode() + b"\r\n")

    def handle(self):
        self.reply("220 sink ESMTP")
        sender, recipients = None, []
        while True:
            line = self.rfile.readline(4096)
            if not line:
                return
            command = line.decode(errors="replace").strip()
            verb = command.split(" ", 1)[0].upper()
            if verb in ("EHLO", "HELO"):
                self.reply("250-sink")
                self.reply("250 8BITMIME")
            elif verb == "MAIL":
                sender, recipients = command.split(":", 1)[1].strip().strip("<>").split(">")[0], []
                self.reply("250 OK")
            elif verb == "RCPT":
                recipients.append(command.split(":", 1)[1].strip().strip("<>").split(">")[0])
                self.reply("250 OK")
            elif verb == "DATA":
                self.reply("354 End data with <CR><LF>.<CR><LF>")
                lines = []
                while True:
                    data = self.rfile.readline(1 << 20)
                    if data in (b".\r\n", b".\n", b""):
                        break
                    lines.append(data[1:] if data.startswith(b"..") else data)
                message = email.message_from_bytes(b"".join(lines), policy=email.policy.default)
                self.server.sink.received.append({"from": sender, "to": recipients, "message": message})
                self.server.sink.arrived.set()
                self.reply("250 OK queued")
            elif verb == "RSET":
                sender, recipients = None, []
                self.reply("250 OK")
            elif verb == "NOOP":
                self.reply("250 OK")
            elif verb == "QUIT":
                self.reply("221 Bye")
                return
            else:
                self.reply("502 Command not implemented")


class _Server(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


class SmtpSink:
    """Start with `with SmtpSink() as sink:`; read `sink.port` and `sink.received`."""

    def __init__(self):
        self.received = []
        self.arrived = threading.Event()
        self._server = _Server(("127.0.0.1", 0), _Handler)
        self._server.sink = self
        self.port = self._server.server_address[1]

    def __enter__(self):
        threading.Thread(target=self._server.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *exc):
        self._server.shutdown()
        self._server.server_close()

    def wait(self, count=1, timeout=5.0):
        """Waits until at least `count` messages arrived; returns them."""
        while len(self.received) < count:
            self.arrived.clear()
            if len(self.received) >= count or not self.arrived.wait(timeout):
                break
        return self.received


def free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]
