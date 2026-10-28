import socket
import sys
import threading
import time

from cryptography.fernet import Fernet, InvalidToken

from common import load_or_create_key, recv_message, send_message

HOST = sys.argv[1] if len(sys.argv) > 1 else "0.0.0.0"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 5555

fernet = Fernet(load_or_create_key())
clients = {}  # socket -> username
lock = threading.Lock()


def stamp():
    return time.strftime("%H:%M")


def broadcast(payload, exclude=None):
    with lock:
        targets = [s for s in clients if s is not exclude]
    for s in targets:
        try:
            send_message(s, fernet, payload)
        except OSError:
            pass  # that client's own thread will clean up


def system_message(text):
    return {"type": "system", "text": text, "time": stamp()}


def handle_client(conn, addr):
    username = None
    try:
        join = recv_message(conn, fernet)
        username = (join.get("user") or "").strip()[:20] or f"guest-{addr[1]}"
        with lock:
            taken = username in clients.values()
        if taken:
            username = f"{username}-{addr[1]}"
        with lock:
            clients[conn] = username
        print(f"[+] {username} joined from {addr[0]}")
        broadcast(system_message(f"{username} joined the chat"))

        while True:
            msg = recv_message(conn, fernet)
            text = (msg.get("text") or "").strip()
            if text:
                broadcast({"type": "msg", "user": username,
                           "text": text[:2000], "time": stamp()})
    except InvalidToken:
        print(f"[!] {addr[0]} sent a message that failed decryption (wrong key?)")
    except (ConnectionError, OSError, ValueError):
        pass
    finally:
        with lock:
            clients.pop(conn, None)
        conn.close()
        if username:
            print(f"[-] {username} left")
            broadcast(system_message(f"{username} left the chat"))


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen()
    print(f"Server listening on {HOST}:{PORT} (key file: secret.key)")
    try:
        while True:
            conn, addr = server.accept()
            threading.Thread(target=handle_client, args=(conn, addr),
                             daemon=True).start()
    except KeyboardInterrupt:
        print("\nShutting down.")
    finally:
        server.close()


if __name__ == "__main__":
    main()
