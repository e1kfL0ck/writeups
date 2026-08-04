#!/usr/bin/env python3

import ssl
import sys
import tty
import termios
import threading
import websocket

URL = "wss://nb-1be3782a8afd3ad5.cohort.htb/terminal/ws"


def recv_loop(ws):
    while True:
        try:
            data = ws.recv()

            if data is None:
                break

            if isinstance(data, bytes):
                sys.stdout.buffer.write(data)
                sys.stdout.buffer.flush()
            else:
                sys.stdout.write(data)
                sys.stdout.flush()

        except Exception:
            break


def send_loop(ws):
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)

    try:
        tty.setraw(fd)

        while True:
            ch = sys.stdin.read(1)

            if not ch:
                break

            ws.send(ch)

    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)


def main():
    ws = websocket.WebSocket(
        sslopt={
            "cert_reqs": ssl.CERT_NONE,
            "check_hostname": False,
        }
    )

    print(f"[*] Connecting to {URL}")
    ws.connect(URL)
    print("[+] Connected\n")

    t = threading.Thread(target=recv_loop, args=(ws,), daemon=True)
    t.start()

    try:
        send_loop(ws)
    except KeyboardInterrupt:
        pass
    finally:
        ws.close()


if __name__ == "__main__":
    main()
