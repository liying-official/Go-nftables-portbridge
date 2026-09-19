#!/usr/bin/env python3
"""Bounded fixture for isolated namespace integration tests; never a daemon."""
import json, socket, sys, threading

def emit(value):
    print(json.dumps(value, separators=(",", ":")), flush=True)

def endpoint(host, port):
    if "%" in host:
        address, interface = host.rsplit("%", 1)
        return (address, port, 0, socket.if_nametoindex(interface))
    return (host, port)

if sys.argv[1] == "server":
    addresses = json.loads(sys.argv[2])
    ports = json.loads(sys.argv[3])
    sockets = []
    slots = threading.BoundedSemaphore(64)
    def tcp_connection(c, label):
        try:
            c.settimeout(90)
            stream = c.makefile("rb")
            while True:
                data = stream.readline(4097)
                if not data or len(data) > 4096:
                    break
                c.sendall(label + b"|" + data)
        except OSError:
            pass
        finally:
            c.close()
            slots.release()
    def tcp_accept(s, label):
        while True:
            try:
                c, _ = s.accept()
            except OSError:
                return
            if not slots.acquire(blocking=False):
                c.close()
                continue
            threading.Thread(target=tcp_connection, args=(c, label), daemon=True).start()
    def udp_echo(s, label):
        while True:
            try:
                data, address = s.recvfrom(4096)
                s.sendto(label + b"|" + data, address)
            except OSError:
                return
    for address in addresses:
        family = socket.AF_INET6 if ":" in address else socket.AF_INET
        for port in ports:
            label = (address + ":" + str(port)).encode()
            for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
                s = socket.socket(family, kind)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                if family == socket.AF_INET6:
                    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                s.bind((address, port))
                sockets.append(s)
                if kind == socket.SOCK_STREAM:
                    s.listen(16)
                    fn = tcp_accept
                else:
                    fn = udp_echo
                threading.Thread(target=fn, args=(s, label), daemon=True).start()
    emit({"ready": True})
    sys.stdin.buffer.read()
    for s in sockets:
        s.close()
elif sys.argv[1] == "client":
    connections = {}
    emit({"ready": True})
    for line in sys.stdin:
        try:
            q = json.loads(line)
            op, name = q["op"], q.get("id", "")
            if op == "open":
                if name in connections:
                    connections.pop(name)[0].close()
                if len(connections) >= 64:
                    raise ValueError("fixture connection bound")
                family = socket.AF_INET6 if q["family"] == 6 else socket.AF_INET
                kind = socket.SOCK_STREAM if q["protocol"] == "tcp" else socket.SOCK_DGRAM
                s = socket.socket(family, kind)
                s.settimeout(0.8)
                try:
                    if q.get("source"):
                        s.bind(endpoint(q["source"], q.get("source_port", 0)))
                    s.connect(endpoint(q["host"], q["port"]))
                except Exception:
                    s.close()
                    raise
                connections[name] = (s, kind)
                emit({"ok": True, "source_port": s.getsockname()[1]})
            elif op == "request":
                s, kind = connections[name]
                data = q["data"].encode()
                if len(data) > 2048:
                    raise ValueError("fixture payload bound")
                if kind == socket.SOCK_STREAM:
                    s.sendall(data + b"\n")
                    response = bytearray()
                    while not response.endswith(b"\n") and len(response) <= 4096:
                        chunk = s.recv(4096-len(response))
                        if not chunk:
                            raise EOFError()
                        response += chunk
                    response = bytes(response).rstrip(b"\n")
                else:
                    s.send(data)
                    response = s.recv(4096)
                emit({"ok": True, "data": response.decode("ascii")})
            elif op == "close":
                if name in connections:
                    connections.pop(name)[0].close()
                emit({"ok": True})
            else:
                raise ValueError("unknown fixture operation")
        except Exception as e:
            emit({"ok": False, "error": type(e).__name__})
    for s, _ in connections.values():
        s.close()
elif sys.argv[1] == "dns":
    import ipaddress, struct
    records, failed = {}, [False]
    lock = threading.Lock()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    def answer():
        while True:
            try:
                request, peer = s.recvfrom(1500)
                if len(request) < 17:
                    continue
                pos, labels = 12, []
                while pos < len(request) and request[pos]:
                    size = request[pos]
                    if size > 63 or pos + size + 1 > len(request):
                        raise ValueError("invalid fixture DNS label")
                    labels.append(request[pos+1:pos+size+1].decode("ascii"))
                    pos += size + 1
                end = pos + 5
                if end > len(request):
                    continue
                qtype = struct.unpack("!H", request[pos+1:pos+3])[0]
                with lock:
                    address = records.get(".".join(labels).lower())
                    is_failed = failed[0]
                payload = b""
                if not is_failed and address:
                    ip = ipaddress.ip_address(address)
                    if qtype == (1 if ip.version == 4 else 28):
                        payload = b"\xc0\x0c" + struct.pack("!HHIH", qtype, 1, 0, len(ip.packed)) + ip.packed
                flags = 0x8182 if is_failed else 0x8180
                response = request[:2] + struct.pack("!HHHHH", flags, 1, int(bool(payload)), 0, 0)
                s.sendto(response + request[12:end] + payload, peer)
            except OSError:
                return
            except (ValueError, UnicodeError):
                continue
    threading.Thread(target=answer, daemon=True).start()
    emit({"ready": True, "port": s.getsockname()[1]})
    for line in sys.stdin:
        q = json.loads(line)
        with lock:
            if q["op"] == "set":
                if len(q["name"]) > 253 or len(records) >= 16 and q["name"] not in records:
                    raise ValueError("fixture DNS bound")
                records[q["name"].lower()] = str(ipaddress.ip_address(q["address"]))
            elif q["op"] == "fail":
                failed[0] = bool(q["value"])
            else:
                raise ValueError("unknown DNS fixture operation")
        emit({"ok": True})
    s.close()
else:
    raise SystemExit("unknown fixture role")
