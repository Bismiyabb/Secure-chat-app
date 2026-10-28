import queue
import socket
import threading
import tkinter as tk
from tkinter import messagebox, simpledialog

from cryptography.fernet import Fernet, InvalidToken

from common import load_key, recv_message, send_message


class ChatClient:
    def __init__(self, root, sock, fernet, username):
        self.root = root
        self.sock = sock
        self.fernet = fernet
        self.username = username
        self.incoming = queue.Queue()

        root.title(f"Secure Chat - {username}")
        root.geometry("520x480")

        self.log = tk.Text(root, state="disabled", wrap="word", padx=8, pady=8)
        self.log.pack(fill="both", expand=True, padx=8, pady=(8, 4))
        self.log.tag_config("system", foreground="gray")
        self.log.tag_config("me", foreground="#1a5fb4")
        self.log.tag_config("other", foreground="#26a269")

        bottom = tk.Frame(root)
        bottom.pack(fill="x", padx=8, pady=(0, 8))
        self.entry = tk.Entry(bottom)
        self.entry.pack(side="left", fill="x", expand=True)
        self.entry.bind("<Return>", self.send)
        self.entry.focus()
        tk.Button(bottom, text="Send", command=self.send).pack(side="left", padx=(6, 0))

        root.protocol("WM_DELETE_WINDOW", self.close)
        threading.Thread(target=self.receive_loop, daemon=True).start()
        self.root.after(100, self.process_incoming)

    def receive_loop(self):
        """Background thread: never touches Tk, only feeds the queue."""
        try:
            while True:
                self.incoming.put(recv_message(self.sock, self.fernet))
        except InvalidToken:
            self.incoming.put({"type": "system", "text": "Decryption failed - wrong key?", "time": ""})
        except (ConnectionError, OSError, ValueError):
            self.incoming.put({"type": "system", "text": "Disconnected from server.", "time": ""})

    def process_incoming(self):
        while not self.incoming.empty():
            self.show(self.incoming.get())
        self.root.after(100, self.process_incoming)

    def show(self, m):
        if m["type"] == "system":
            line, tag = f"* {m['text']}\n", "system"
        else:
            tag = "me" if m["user"] == self.username else "other"
            line = f"[{m['time']}] {m['user']}: {m['text']}\n"
        self.log.config(state="normal")
        self.log.insert("end", line, tag)
        self.log.config(state="disabled")
        self.log.see("end")

    def send(self, event=None):
        text = self.entry.get().strip()
        if not text:
            return
        try:
            send_message(self.sock, self.fernet, {"type": "msg", "text": text})
            self.entry.delete(0, "end")
        except OSError:
            messagebox.showerror("Error", "Could not send - connection lost.")

    def close(self):
        try:
            self.sock.close()
        finally:
            self.root.destroy()


def main():
    root = tk.Tk()
    root.withdraw()
    username = simpledialog.askstring("Username", "Choose a username:", parent=root)
    host = simpledialog.askstring("Server", "Server address:", initialvalue="127.0.0.1", parent=root)
    if not username or not host:
        return
    try:
        fernet = Fernet(load_key())
    except FileNotFoundError:
        messagebox.showerror("Missing key", "secret.key not found. Copy it from the server folder.")
        return
    try:
        sock = socket.create_connection((host, 5555), timeout=5)
        sock.settimeout(None)
        send_message(sock, fernet, {"type": "join", "user": username})
    except OSError as e:
        messagebox.showerror("Connection failed", str(e))
        return
    root.deiconify()
    ChatClient(root, sock, fernet, username)
    root.mainloop()


if __name__ == "__main__":
    main()
