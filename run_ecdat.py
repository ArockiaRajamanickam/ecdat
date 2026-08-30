#!/usr/bin/env python3
"""One-click launcher for ECDAT.

Double-click the executable (Windows / macOS / Linux) and it starts the local
ECDAT server and opens your browser. Everything runs on your own machine; your
code never leaves it. No Python, pip, or internet required.
"""
import os, sys, socket, threading, time, webbrowser

os.environ.setdefault("ECDAT_LOCAL", "1")   # local runs can scan folders on this machine

def pick_port(preferred=8000):
    for p in (preferred, 8001, 8080, 8765):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(("127.0.0.1", p)) != 0:
                return p
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]

def main():
    port = pick_port()
    url = f"http://127.0.0.1:{port}"
    banner = (
        "\n  ECDAT — Enterprise Cryptographic Discovery\n"
        f"  Running at {url}\n"
        "  Your browser should open automatically. Keep this window open while you use ECDAT.\n"
        "  Close this window (or press Ctrl+C) to stop.\n"
    )
    print(banner, flush=True)

    def open_browser():
        # wait until the server actually accepts connections (first run extracts, ~10s)
        for _ in range(120):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                if s.connect_ex(("127.0.0.1", port)) == 0:
                    break
            time.sleep(0.4)
        try: webbrowser.open(url)
        except Exception: pass
    threading.Thread(target=open_browser, daemon=True).start()

    import asyncio, uvicorn
    from app.server import app
    # Pure-Python loop/protocol so the frozen binary needs no uvloop/httptools native modules.
    config = uvicorn.Config(app, host="127.0.0.1", port=port,
                            loop="asyncio", http="h11", ws="none", log_level="info")
    server = uvicorn.Server(config)
    server.install_signal_handlers = lambda: None   # signal handlers can hang in a frozen app
    asyncio.run(server.serve())

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
    except Exception:
        import traceback
        traceback.print_exc()
        try: input("\nECDAT hit an error. Press Enter to close…")
        except Exception: pass
