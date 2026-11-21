import json
import socket
import threading

import pytest

from pwnscan import tcp


def test_tcp_steps_validate_without_execution(tmp_path):
    steps = tmp_path / "steps.json"
    steps.write_text(json.dumps([
        {"recv_until": "Ready>"},
        {"send": "hello\n"},
        {"send_hex": "4142"},
    ]), encoding="utf-8")
    assert tcp.main([str(steps)]) == 0


@pytest.mark.parametrize("data", [
    [{"send": "A", "recv_until": "B"}],
    [{"invalid": "x"}],
    [{"send_hex": "xyz"}],
    [{"recv_until": ""}],
    [{"send": "A" * 4097}],
    [],
])
def test_tcp_rejects_invalid_steps(tmp_path, data):
    path = tmp_path / "invalid.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError):
        tcp.load_steps(path)


def test_tcp_dialogue_against_local_loopback_only(tmp_path):
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    failures = []

    def serve():
        try:
            conn, _ = server.accept()
            with conn:
                conn.sendall(b"Ready>")
                incoming = conn.recv(128)
                if incoming != b"hello\n":
                    failures.append(incoming)
                conn.sendall(b"CTF{proof_only}\n")
        finally:
            server.close()

    thread = threading.Thread(target=serve)
    thread.start()
    steps = tmp_path / "steps.json"
    steps.write_text(json.dumps([
        {"recv_until": "Ready>"},
        {"send": "hello\n"},
        {"recv_until": "\n"},
    ]), encoding="utf-8")
    try:
        assert tcp.main([str(steps), "--execute", "--port", str(port)]) == 0
    finally:
        thread.join(timeout=5)
    assert not failures


def test_tcp_does_not_claim_flag_from_plain_text(tmp_path, capsys):
    steps = tmp_path / "steps.json"
    steps.write_text('[{"send":"hello"}]', encoding="utf-8")
    assert tcp.main([str(steps)]) == 0
    assert "no connection made" in capsys.readouterr().out
