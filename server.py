"""
SecureChat Server v4.0 — Educational Cybersecurity TCP Chat Server
══════════════════════════════════════════════════════════════════════
Upgrades over v3.0:
  ★ Rate limiting per user (burst + sustained)
  ★ IP-level ban list with persistence (banned_ips.txt)
  ★ Per-user connection tracking (concurrent + total)
  ★ Threat-pattern detection with configurable severity levels
  ★ Watchlist system — flag users for passive surveillance
  ★ /wall  — operator MOTD broadcast (seen by new joiners too)
  ★ /shadow <user> — ghost-mute (user sees own msgs, others don't)
  ★ /rename <old> <new> — operator-rename a connected user
  ★ /tempban <user> <seconds> — timed kick + lockout
  ★ /notes <user> <text> — operator scratch-pad per user
  ★ /search <keyword> — search message history buffer
  ★ /export — dump audit log to timestamped CSV
  ★ /uptime — server runtime stats
  ★ /ping <user> — latency probe to a client
  ★ Graceful shutdown with client notification countdown
  ★ Config file (server_config.ini) with hot-reload (/reload)
  ★ Structured JSON audit log option
  ★ Console colour output (ANSI)
  ★ Improved buffering — handles split TCP packets correctly
  ★ All original v3.0 features preserved
"""

import socket
import threading
import os
import re
import datetime
import collections
import time
import shlex
import json
import csv
import configparser
import signal
import sys
from typing import Optional

# ─────────────────────────────────────────────────────────────────────────────
# ANSI COLOUR HELPERS
# ─────────────────────────────────────────────────────────────────────────────
_ANSI = sys.stdout.isatty()   # only colour when attached to a real terminal

def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _ANSI else text

def red(t):    return _c("31", t)
def green(t):  return _c("32", t)
def yellow(t): return _c("33", t)
def cyan(t):   return _c("36", t)
def bold(t):   return _c("1",  t)
def grey(t):   return _c("90", t)


# ─────────────────────────────────────────────────────────────────────────────
# DEFAULTS  (overridden by server_config.ini if present)
# ─────────────────────────────────────────────────────────────────────────────
DEFAULT_CONFIG = {
    "host"            : "0.0.0.0",
    "port"            : "9999",
    "max_clients"     : "20",
    "audit_log"       : "chat_audit.log",
    "audit_json"      : "False",
    "max_history"     : "500",
    "rate_limit_burst": "8",        # max msgs in the window
    "rate_limit_window": "5",       # seconds
    "rshell_timeout"  : "15",       # seconds
    "motd"            : "Welcome to SecureChat v4.0!",
    "banned_ips_file" : "banned_ips.txt",
    "notes_file"      : "operator_notes.json",
}

cfg = configparser.ConfigParser()

def load_config() -> dict:
    """Load server_config.ini; fall back to defaults for missing keys."""
    cfg.read("server_config.ini")
    section = cfg["server"] if "server" in cfg else {}
    merged  = {k: section.get(k, v) for k, v in DEFAULT_CONFIG.items()}
    return merged

CONF = load_config()

SERVER_HOST   = CONF["host"]
SERVER_PORT   = int(CONF["port"])
MAX_CLIENTS   = int(CONF["max_clients"])
AUDIT_LOG     = CONF["audit_log"]
AUDIT_JSON    = CONF["audit_json"].lower() == "true"
MAX_HISTORY   = int(CONF["max_history"])
RATE_BURST    = int(CONF["rate_limit_burst"])
RATE_WINDOW   = int(CONF["rate_limit_window"])
RSHELL_TIMEOUT= int(CONF["rshell_timeout"])
BANNED_IPS_FILE = CONF["banned_ips_file"]
NOTES_FILE    = CONF["notes_file"]


# ─────────────────────────────────────────────────────────────────────────────
# THREAT PATTERNS  (configurable severity)
# ─────────────────────────────────────────────────────────────────────────────
THREAT_PATTERNS = [
    # (compiled_regex, severity, label)
    (re.compile(r'\b(rm\s+-rf|format\s+c:|del\s+/[fqs])\b', re.I), "CRITICAL", "DESTRUCTIVE_CMD"),
    (re.compile(r'(bash\s+-i|nc\s+-e|ncat\s+.*-e|\/bin\/sh)',  re.I), "HIGH",     "REVERSE_SHELL"),
    (re.compile(r'(wget|curl)\s+http',                          re.I), "MEDIUM",   "DOWNLOAD_ATTEMPT"),
    (re.compile(r'\b(password|passwd|secret|token|apikey)\b',   re.I), "LOW",      "SENSITIVE_KEYWORD"),
    (re.compile(r'(SELECT|INSERT|DROP|UNION)\s+',               re.I), "MEDIUM",   "SQL_PATTERN"),
    (re.compile(r'<script[\s>]',                                re.I), "MEDIUM",   "XSS_PATTERN"),
    (re.compile(r'\b(sudo|su\s+-|chmod\s+[0-7]*7)\b',          re.I), "LOW",      "PRIV_ESCALATION"),
]


# ─────────────────────────────────────────────────────────────────────────────
# PROTOCOL TAGS
# ─────────────────────────────────────────────────────────────────────────────
RSHELL_REQ_TAG = "__RSHELL_REQ__:"
RSHELL_RES_TAG = "__RSHELL_RES__:"
RSHELL_END_TAG = "__RSHELL_END__"
PING_REQ_TAG   = "__PING_REQ__:"
PING_RES_TAG   = "__PING_RES__:"


# ─────────────────────────────────────────────────────────────────────────────
# SHARED SERVER STATE
# ─────────────────────────────────────────────────────────────────────────────
_state_lock    = threading.Lock()

clients        : dict[str, socket.socket]   = {}   # username → socket
client_addrs   : dict[str, tuple]           = {}   # username → (ip, port)
admins         : set[str]                   = set()
frozen         : set[str]                   = set()
shadowed       : set[str]                   = set()   # ghost-muted users
watchlist      : set[str]                   = set()
spy_mode       : list                       = [False]
msg_history    : collections.deque          = collections.deque(maxlen=MAX_HISTORY)
motd           : list                       = [CONF["motd"]]
banned_ips     : set[str]                   = set()
tempban_ends   : dict[str, float]           = {}    # ip → epoch when ban lifts
ip_connection_count : dict[str, int]        = collections.defaultdict(int)
rate_buckets   : dict[str, list]            = {}    # username → [timestamps]
operator_notes : dict[str, list]            = {}    # username → [note strings]
server_start   : float                      = time.time()

# Remote-shell state
rshell_events  : dict[str, threading.Event] = {}
rshell_results : dict[str, str]             = {}

# Ping state
ping_events    : dict[str, threading.Event] = {}
ping_sent_at   : dict[str, float]           = {}

stats = {
    "total_messages"   : 0,
    "private_messages" : 0,
    "exec_attempts"    : 0,
    "blocked_attempts" : 0,
    "connections_total": 0,
    "remote_shell_runs": 0,
    "threats_caught"   : 0,
    "rate_violations"  : 0,
}


# ─────────────────────────────────────────────────────────────────────────────
# BANNED IP PERSISTENCE
# ─────────────────────────────────────────────────────────────────────────────

def load_banned_ips() -> None:
    try:
        with open(BANNED_IPS_FILE, "r", encoding="utf-8") as f:
            for line in f:
                ip = line.strip()
                if ip and not ip.startswith("#"):
                    banned_ips.add(ip)
        if banned_ips:
            print(green(f"[+] Loaded {len(banned_ips)} banned IP(s) from {BANNED_IPS_FILE}"))
    except FileNotFoundError:
        pass


def save_banned_ips() -> None:
    try:
        with open(BANNED_IPS_FILE, "w", encoding="utf-8") as f:
            f.write("# SecureChat banned IPs — one per line\n")
            for ip in sorted(banned_ips):
                f.write(ip + "\n")
    except OSError:
        pass


# ─────────────────────────────────────────────────────────────────────────────
# OPERATOR NOTES PERSISTENCE
# ─────────────────────────────────────────────────────────────────────────────

def load_notes() -> None:
    global operator_notes
    try:
        with open(NOTES_FILE, "r", encoding="utf-8") as f:
            operator_notes = json.load(f)
        print(green(f"[+] Loaded operator notes from {NOTES_FILE}"))
    except (FileNotFoundError, json.JSONDecodeError):
        operator_notes = {}


def save_notes() -> None:
    try:
        with open(NOTES_FILE, "w", encoding="utf-8") as f:
            json.dump(operator_notes, f, indent=2)
    except OSError:
        pass


# ─────────────────────────────────────────────────────────────────────────────
# AUDIT LOGGER
# ─────────────────────────────────────────────────────────────────────────────

def audit(event: str, actor: str = "SERVER", detail: str = "",
          severity: str = "INFO") -> None:
    """Write to audit log (plaintext or JSON) and print colour-coded to console."""
    now     = datetime.datetime.now()
    ts_full = now.strftime("%Y-%m-%d %H:%M:%S")
    ts_disp = now.strftime("%H:%M:%S")

    # Console colour by severity
    colour_map = {"CRITICAL": red, "HIGH": red, "MEDIUM": yellow,
                  "LOW": cyan, "INFO": grey}
    colourise = colour_map.get(severity, grey)

    console_line = colourise(f"[{ts_disp}][{event:<22}] {actor:<15} {detail}")
    print(console_line)

    try:
        if AUDIT_JSON:
            entry = {
                "ts": ts_full, "event": event, "actor": actor,
                "detail": detail, "severity": severity
            }
            with open(AUDIT_LOG, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
        else:
            line = f"[{ts_full}] [{severity:<8}] [{event:<22}] actor={actor:<15} {detail}"
            with open(AUDIT_LOG, "a", encoding="utf-8") as f:
                f.write(line + "\n")
    except OSError:
        pass


# ─────────────────────────────────────────────────────────────────────────────
# RATE LIMITER
# ─────────────────────────────────────────────────────────────────────────────

def check_rate_limit(username: str) -> bool:
    """
    Token-bucket style rate limiting.
    Returns True if the message is ALLOWED, False if it exceeds the limit.
    """
    now    = time.time()
    bucket = rate_buckets.setdefault(username, [])
    # Purge timestamps outside the window
    rate_buckets[username] = [t for t in bucket if now - t < RATE_WINDOW]
    if len(rate_buckets[username]) >= RATE_BURST:
        return False
    rate_buckets[username].append(now)
    return True


# ─────────────────────────────────────────────────────────────────────────────
# THREAT SCANNER
# ─────────────────────────────────────────────────────────────────────────────

def scan_for_threats(text: str, username: str) -> Optional[tuple]:
    """
    Scan a message for threat patterns.
    Returns (severity, label) of the first match, or None.
    """
    for pattern, severity, label in THREAT_PATTERNS:
        if pattern.search(text):
            stats["threats_caught"] += 1
            audit("THREAT_DETECTED", actor=username,
                  detail=f"pattern={label} severity={severity} msg={text[:80]!r}",
                  severity=severity)
            if username in watchlist:
                print(red(f"  ⚠ WATCHLIST HIT — {username}: {label} ({severity})"))
            return severity, label
    return None


# ─────────────────────────────────────────────────────────────────────────────
# NETWORK HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def send(sock: socket.socket, message: str) -> None:
    try:
        sock.sendall((message + "\n").encode("utf-8"))
    except (BrokenPipeError, OSError):
        pass


def broadcast(message: str, exclude: str = "") -> None:
    with _state_lock:
        targets = [(u, s) for u, s in clients.items() if u != exclude]
    for _, sock in targets:
        send(sock, message)


def broadcast_to_role(message: str, role: str = "all", exclude: str = "") -> None:
    """Send to admins only, or all."""
    with _state_lock:
        if role == "admins":
            targets = [(u, s) for u, s in clients.items()
                       if u in admins and u != exclude]
        else:
            targets = [(u, s) for u, s in clients.items() if u != exclude]
    for _, sock in targets:
        send(sock, message)


# ─────────────────────────────────────────────────────────────────────────────
# USER MANAGEMENT HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def remove_client(username: str) -> None:
    """Remove user from all state structures."""
    with _state_lock:
        addr = client_addrs.pop(username, None)
        clients.pop(username, None)
    admins.discard(username)
    frozen.discard(username)
    shadowed.discard(username)
    watchlist.discard(username)
    rshell_events.pop(username, None)
    rshell_results.pop(username, None)
    rate_buckets.pop(username, None)
    if addr:
        ip = addr[0]
        ip_connection_count[ip] = max(0, ip_connection_count[ip] - 1)


def record_and_spy(sender: str, recipient: str, text: str,
                   msg_type: str = "PUBLIC") -> None:
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    entry = {"ts": ts, "sender": sender, "recipient": recipient,
             "type": msg_type, "text": text}
    msg_history.append(entry)
    if spy_mode[0]:
        tag = f"[SPY|{msg_type}]"
        if msg_type == "PRIVATE":
            print(yellow(f"    {tag} {sender} → {recipient}: {text}"))
        else:
            print(yellow(f"    {tag} {sender}: {text}"))


def list_users_detailed() -> str:
    with _state_lock:
        if not clients:
            return "  No users connected."
        lines = [f"  {'Username':<20} {'Role':<8} {'Status':<10} {'IP':<15} Msgs"]
        lines.append("  " + "─" * 60)
        for uname in clients:
            role   = "ADMIN"    if uname in admins   else "user"
            status = "FROZEN"   if uname in frozen   else \
                     "SHADOWED" if uname in shadowed  else \
                     "WATCH"    if uname in watchlist else "active"
            ip     = client_addrs.get(uname, ("?",))[0]
            msgs   = sum(1 for m in msg_history if m["sender"] == uname)
            lines.append(f"  {uname:<20} {role:<8} {status:<10} {ip:<15} {msgs}")
    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# REMOTE SHELL
# ─────────────────────────────────────────────────────────────────────────────

def remote_exec_on_client(target_user: str, command: str,
                          timeout: int = RSHELL_TIMEOUT) -> str:
    with _state_lock:
        target_sock = clients.get(target_user)
    if not target_sock:
        return f"[!] '{target_user}' is not connected."

    event = threading.Event()
    rshell_events[target_user]  = event
    rshell_results.pop(target_user, None)

    try:
        target_sock.sendall((RSHELL_REQ_TAG + command + "\n").encode("utf-8"))
    except (BrokenPipeError, OSError) as e:
        rshell_events.pop(target_user, None)
        return f"[!] Failed to send command: {e}"

    got = event.wait(timeout=timeout)
    rshell_events.pop(target_user, None)

    if not got:
        return f"[!] Timed out waiting for '{target_user}' ({timeout}s)."
    return rshell_results.pop(target_user, "(no output received)")


def _print_rshell_box(target: str, cmd: str, output: str) -> None:
    sep = "═" * 50
    print(f"\n  ╔{sep}")
    print(f"  ║  {bold('Target')}  : {cyan(target)}")
    print(f"  ║  {bold('Command')} : $ {cmd}")
    print(f"  ╠{sep}")
    for ln in output.splitlines():
        print(f"  ║  {ln}")
    print(f"  ╚{sep}\n")


# ─────────────────────────────────────────────────────────────────────────────
# PING HELPER
# ─────────────────────────────────────────────────────────────────────────────

def ping_client(target_user: str, timeout: int = 5) -> str:
    """Send a ping probe and measure round-trip time."""
    with _state_lock:
        sock = clients.get(target_user)
    if not sock:
        return f"[!] '{target_user}' is not connected."

    event = threading.Event()
    ping_events[target_user] = event
    ts = time.time()
    ping_sent_at[target_user] = ts

    try:
        sock.sendall((PING_REQ_TAG + str(ts) + "\n").encode("utf-8"))
    except (BrokenPipeError, OSError) as e:
        ping_events.pop(target_user, None)
        return f"[!] Send failed: {e}"

    got = event.wait(timeout=timeout)
    ping_events.pop(target_user, None)
    ping_sent_at.pop(target_user, None)

    if not got:
        return f"[!] {target_user} did not respond within {timeout}s."
    rtt = (time.time() - ts) * 1000
    return f"PONG from {target_user} — RTT: {rtt:.1f} ms"


# ─────────────────────────────────────────────────────────────────────────────
# TEMPORARY BAN
# ─────────────────────────────────────────────────────────────────────────────

def apply_tempban(ip: str, seconds: int) -> None:
    banned_ips.add(ip)
    tempban_ends[ip] = time.time() + seconds

    def _lift():
        time.sleep(seconds)
        banned_ips.discard(ip)
        tempban_ends.pop(ip, None)
        save_banned_ips()
        print(green(f"[+] Temp-ban lifted for {ip}"))

    threading.Thread(target=_lift, daemon=True).start()


# ─────────────────────────────────────────────────────────────────────────────
# EXPORT AUDIT LOG → CSV
# ─────────────────────────────────────────────────────────────────────────────

def export_audit_csv() -> str:
    ts   = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    path = f"audit_export_{ts}.csv"
    try:
        with open(AUDIT_LOG, "r", encoding="utf-8") as f:
            raw_lines = f.readlines()
        with open(path, "w", newline="", encoding="utf-8") as csvf:
            writer = csv.writer(csvf)
            writer.writerow(["timestamp", "severity", "event", "actor", "detail"])
            for line in raw_lines:
                # plain log format: [date time] [severity] [event] actor=x detail=y
                m = re.match(
                    r'\[(.+?)\]\s+\[(.+?)\]\s+\[(.+?)\]\s+actor=(\S+)\s+(.*)', line)
                if m:
                    writer.writerow([m.group(1), m.group(2).strip(),
                                     m.group(3).strip(), m.group(4), m.group(5)])
        return f"  ✓ Exported {len(raw_lines)} entries → {path}"
    except FileNotFoundError:
        return "  [!] Audit log not found yet."
    except OSError as e:
        return f"  [!] Export failed: {e}"


# ─────────────────────────────────────────────────────────────────────────────
# CLIENT HANDLER THREAD
# ─────────────────────────────────────────────────────────────────────────────

def handle_client(conn: socket.socket, addr: tuple) -> None:
    """One thread per connected client."""
    ip = addr[0]
    print(green(f"[+] New connection from {addr}"))

    # ── IP ban check ──────────────────────────────────────────────────
    if ip in banned_ips:
        remaining = ""
        if ip in tempban_ends:
            secs = int(tempban_ends[ip] - time.time())
            remaining = f" ({max(0, secs)}s remaining)"
        send(conn, f"[SERVER] Your IP is banned{remaining}.")
        conn.close()
        audit("BANNED_REJECT", detail=f"ip={ip}")
        return

    # ── Concurrent connection limit per IP ────────────────────────────
    ip_connection_count[ip] += 1
    if ip_connection_count[ip] > 3:
        send(conn, "[SERVER] Too many connections from your IP.")
        conn.close()
        ip_connection_count[ip] -= 1
        return

    # ── Username prompt ───────────────────────────────────────────────
    send(conn, "╔════════════════════════════════╗\n"
               "║   SecureChat v4.0 — Welcome!   ║\n"
               "╚════════════════════════════════╝\n"
               "Enter your username: ")
    try:
        raw = conn.recv(1024).decode("utf-8").strip()
    except (ConnectionResetError, OSError):
        conn.close()
        ip_connection_count[ip] -= 1
        return

    username = raw.strip()

    if not username or not re.match(r'^[A-Za-z0-9_]{1,20}$', username):
        send(conn, "[SERVER] Invalid username. Use 1-20 alphanumeric/underscore chars.")
        conn.close()
        ip_connection_count[ip] -= 1
        return

    with _state_lock:
        if username in clients:
            send(conn, f"[SERVER] '{username}' is already taken. Try another.")
            conn.close()
            ip_connection_count[ip] -= 1
            return
        clients[username]      = conn
        client_addrs[username] = addr
        stats["connections_total"] += 1

    print(green(f"[+] {username} connected from {addr}"))
    audit("CONNECT", actor=username, detail=f"addr={addr}")

    send(conn, f"[SERVER] Welcome, {username}!\n"
               f"[SERVER] {motd[0]}\n"
               f"[SERVER] Type /help for commands.")
    broadcast(f"[SERVER] ★ {username} has joined the chat.", exclude=username)

    # ── Message loop ─────────────────────────────────────────────────
    recv_buffer = ""

    try:
        while True:
            try:
                data = conn.recv(4096)
            except OSError:
                break
            if not data:
                break

            recv_buffer += data.decode("utf-8", errors="replace")

            # ── Remote-shell response (may be multipart) ──────────────
            if RSHELL_RES_TAG in recv_buffer and RSHELL_END_TAG in recv_buffer:
                start  = recv_buffer.index(RSHELL_RES_TAG) + len(RSHELL_RES_TAG)
                end    = recv_buffer.index(RSHELL_END_TAG)
                output = recv_buffer[start:end]
                recv_buffer = recv_buffer[end + len(RSHELL_END_TAG):].lstrip("\n")
                rshell_results[username] = output
                ev = rshell_events.get(username)
                if ev:
                    ev.set()
                continue

            # ── Ping response ─────────────────────────────────────────
            if PING_RES_TAG in recv_buffer and "\n" in recv_buffer:
                idx = recv_buffer.index(PING_RES_TAG)
                end = recv_buffer.index("\n", idx)
                recv_buffer = recv_buffer[:idx] + recv_buffer[end+1:]
                ev = ping_events.get(username)
                if ev:
                    ev.set()
                continue

            # ── Split into complete lines ─────────────────────────────
            lines = recv_buffer.split("\n")
            recv_buffer = lines.pop()   # keep partial tail

            for line in lines:
                raw = line.strip()
                if not raw:
                    continue

                # Rate limiter (exempt admins from rate limiting)
                if username not in admins:
                    if not check_rate_limit(username):
                        stats["rate_violations"] += 1
                        send(conn, "[SERVER] ⚠ Rate limit exceeded. Slow down.")
                        audit("RATE_LIMIT", actor=username,
                              detail=f"msg={raw[:60]!r}", severity="LOW")
                        continue

                # ── Threat scan on all messages ───────────────────────
                threat = scan_for_threats(raw, username)

                # ── /help ─────────────────────────────────────────────
                if raw == "/help":
                    is_admin = username in admins
                    help_txt = [
                        "\n[SERVER] Available commands:",
                        "  /users              — list connected users",
                        "  /msg <user> <text>  — private message",
                        "  /admins             — list online admins",
                        "  /status             — your role/status",
                        "  /quit               — disconnect",
                    ]
                    if is_admin:
                        help_txt += [
                            "\n  [ADMIN]",
                            '  /exec <user> "<cmd>"  — run command on target client',
                        ]
                    send(conn, "\n".join(help_txt) + "\n")

                # ── /users ────────────────────────────────────────────
                elif raw == "/users":
                    with _state_lock:
                        user_lines = []
                        for uname in clients:
                            tag  = " [ADMIN]"   if uname in admins    else ""
                            tag += " [FROZEN]"  if uname in frozen    else ""
                            tag += " [SHADOW]"  if uname in shadowed  else ""
                            user_lines.append(f"  • {uname}{tag}")
                    send(conn, "[SERVER] Online:\n" + "\n".join(user_lines))

                # ── /admins ───────────────────────────────────────────
                elif raw == "/admins":
                    with _state_lock:
                        online_admins = [a for a in admins if a in clients]
                    send(conn, "[SERVER] Admins: " + (", ".join(online_admins) or "none"))

                # ── /status ───────────────────────────────────────────
                elif raw == "/status":
                    role = "ADMIN" if username in admins else "user"
                    frz  = " | FROZEN"   if username in frozen   else ""
                    shd  = " | SHADOWED" if username in shadowed else ""
                    wtch = " | WATCHED"  if username in watchlist else ""
                    send(conn, f"[SERVER] {username} | Role: {role}{frz}{shd}{wtch}")

                # ── /quit ─────────────────────────────────────────────
                elif raw == "/quit":
                    send(conn, "[SERVER] Goodbye!")
                    break

                # ── /msg <target> <text> ──────────────────────────────
                elif raw.startswith("/msg "):
                    parts = raw.split(" ", 2)
                    if len(parts) < 3:
                        send(conn, "[SERVER] Usage: /msg <username> <message>")
                        continue
                    target, pm_text = parts[1], parts[2]
                    record_and_spy(username, target, pm_text, "PRIVATE")
                    with _state_lock:
                        target_sock = clients.get(target)
                    if target_sock:
                        send(target_sock, f"[PM from {username}] {pm_text}")
                        send(conn,        f"[PM to {target}] {pm_text}")
                        stats["private_messages"] += 1
                        audit("PRIVATE_MSG", actor=username, detail=f"to={target}")
                    else:
                        send(conn, f"[SERVER] User '{target}' not found.")

                # ── /exec <target> "<cmd>" ────────────────────────────
                elif raw.startswith("/exec "):
                    stats["exec_attempts"] += 1
                    if username not in admins:
                        stats["blocked_attempts"] += 1
                        audit("EXEC_DENIED", actor=username, detail=f"raw={raw!r}",
                              severity="MEDIUM")
                        record_and_spy(username, "SERVER", raw, "EXEC-DENIED")
                        # Still broadcast so other users see the message
                        broadcast(f"[{username}] {raw}", exclude=username)
                        send(conn, f"[you] {raw}")
                    else:
                        rest = raw[6:].strip()
                        try:
                            tokens = shlex.split(rest)
                        except ValueError:
                            tokens = rest.split(" ", 1)

                        if len(tokens) < 2:
                            send(conn, '[SERVER] Usage: /exec <username> "<command>"')
                            continue

                        tu       = tokens[0]
                        ci       = " ".join(tokens[1:])
                        req_user = username

                        with _state_lock:
                            connected = tu in clients

                        if not connected:
                            send(conn, f"[SERVER] '{tu}' is not connected.")
                            continue

                        audit("EXEC_SEND", actor=req_user,
                              detail=f"target={tu} cmd={ci!r}", severity="HIGH")
                        stats["remote_shell_runs"] += 1
                        send(conn, f'[SERVER ⚙] Running "{ci}" on {tu}\'s machine...')

                        def _run(tu=tu, ci=ci, req=req_user):
                            out = remote_exec_on_client(tu, ci)
                            _print_rshell_box(tu, ci, out)
                            with _state_lock:
                                req_sock = clients.get(req)
                            if req_sock:
                                send(req_sock, f"[RSHELL ⚙ {tu}] $ {ci}\n{out}")
                            audit("RSHELL_RESULT", actor=req,
                                  detail=f"target={tu} cmd={ci!r} out={out[:120]!r}")

                        threading.Thread(target=_run, daemon=True).start()

                # ── plain broadcast ───────────────────────────────────
                else:
                    if username in frozen:
                        send(conn, f"[you] {raw}")
                        record_and_spy(username, "ALL", raw, "FROZEN-DROP")
                        audit("FROZEN_MSG", actor=username, detail=f"msg={raw!r}")
                    elif username in shadowed:
                        # Ghost-mute: user sees own msg, others don't receive it
                        send(conn, f"[you] {raw}")
                        record_and_spy(username, "ALL", raw, "SHADOW-DROP")
                        audit("SHADOW_MSG", actor=username, detail=f"msg={raw!r}",
                              severity="LOW")
                    else:
                        record_and_spy(username, "ALL", raw)
                        broadcast(f"[{username}] {raw}", exclude=username)
                        send(conn, f"[you] {raw}")
                        stats["total_messages"] += 1
                        audit("MESSAGE", actor=username, detail=f"msg={raw!r}")

                        # Watchlist alert
                        if username in watchlist and threat:
                            broadcast_to_role(
                                f"⚠ [WATCHLIST] {username} triggered {threat[1]} "
                                f"({threat[0]})", role="admins")

    except (ConnectionResetError, OSError) as e:
        print(red(f"[-] Error for {username}: {e}"))
    finally:
        remove_client(username)
        conn.close()
        broadcast(f"[SERVER] {username} has left the chat.")
        audit("DISCONNECT", actor=username)
        print(yellow(f"[-] {username} disconnected."))


# ─────────────────────────────────────────────────────────────────────────────
# SERVER CONSOLE HELP
# ─────────────────────────────────────────────────────────────────────────────

CONSOLE_HELP = """
╔══════════════════════════════════════════════════════════════════════╗
║   SecureChat v4.0 — SERVER CONSOLE                                   ║
╠══════════════════════════════════════════════════════════════════════╣
║  COMMUNICATION                                                       ║
║    /broadcast <msg>         — send to all clients                    ║
║    /wall <msg>              — set MOTD (shown to new joiners too)    ║
║    /msg <user> <msg>        — private message a client               ║
║    /alert <user> <msg>      — red-flag warning to a user             ║
║                                                                      ║
║  USER MANAGEMENT                                                     ║
║    /users                   — detailed user table                    ║
║    /inspect <user>          — full profile of a connected user       ║
║    /kick <user>             — forcibly disconnect                    ║
║    /freeze <user>           — silent mute (sender unaware)           ║
║    /unfreeze <user>         — restore voice                          ║
║    /shadow <user>           — ghost-mute (user thinks they're live)  ║
║    /unshadow <user>         — remove shadow                          ║
║    /rename <old> <new>      — rename a connected user                ║
║    /tempban <user> <secs>   — kick + temporary IP ban                ║
║    /banip <ip>              — permanently ban an IP                  ║
║    /unbanip <ip>            — lift a ban                             ║
║    /bans                    — list banned IPs                        ║
║    /notes <user> <text>     — add operator note for a user           ║
║    /shownotes <user>        — view notes for a user                  ║
║                                                                      ║
║  ADMIN SYSTEM                                                        ║
║    /admin <user>            — grant admin privileges                 ║
║    /revoke <user>           — strip admin privileges                 ║
║    /admins                  — list all online admins                 ║
║                                                                      ║
║  MONITORING                                                          ║
║    /sniff                   — toggle spy mode (intercept all msgs)   ║
║    /history [n]             — show last n msgs from buffer (def 20)  ║
║    /search <keyword>        — search message history                 ║
║    /watch <user>            — add to watchlist (alert on threats)    ║
║    /unwatch <user>          — remove from watchlist                  ║
║    /watchlist               — list watched users                     ║
║    /stats                   — live server statistics                 ║
║    /log                     — tail last 20 lines of audit log        ║
║    /export                  — dump audit log to CSV                  ║
║    /uptime                  — server uptime and load info            ║
║    /ping <user>             — measure round-trip latency to client   ║
║                                                                      ║
║  ★ REMOTE SHELL                                                      ║
║    /rshell <user> "<cmd>"   — execute cmd on client, output here     ║
║    Example: /rshell alice "whoami"                                   ║
║    Example: /rshell bob "ls -la /tmp"                                ║
║                                                                      ║
║  CONFIG                                                              ║
║    /reload                  — hot-reload server_config.ini           ║
║                                                                      ║
║  SERVER                                                              ║
║    /help                    — show this menu                         ║
║    /quit [secs]             — graceful shutdown (default 5s warning) ║
╚══════════════════════════════════════════════════════════════════════╝
"""


# ─────────────────────────────────────────────────────────────────────────────
# SERVER CONSOLE LOOP
# ─────────────────────────────────────────────────────────────────────────────

def server_console() -> None:
    """Interactive operator console in its own daemon thread."""
    print(CONSOLE_HELP)

    while True:
        try:
            spy_ind = "👁 " if spy_mode[0] else " > "
            cmd = input(bold(f"SERVER{spy_ind}")).strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[Server] Console closed.")
            break

        if not cmd:
            continue

        # ── /broadcast ────────────────────────────────────────────────
        if cmd.startswith("/broadcast "):
            msg  = cmd[11:]
            full = f"[SERVER] {msg}"
            print(f"  → Broadcast: {full}")
            broadcast(full)
            audit("BROADCAST", detail=f"msg={msg!r}")

        # ── /wall <msg> — MOTD update ────────────────────────────────
        elif cmd.startswith("/wall "):
            motd[0] = cmd[6:]
            broadcast(f"[SERVER] 📢 MOTD updated: {motd[0]}")
            audit("MOTD_SET", detail=f"motd={motd[0]!r}")
            print(f"  → MOTD set: {motd[0]}")

        # ── /msg ──────────────────────────────────────────────────────
        elif cmd.startswith("/msg "):
            parts = cmd.split(" ", 2)
            if len(parts) == 3:
                target, msg = parts[1], parts[2]
                with _state_lock:
                    sock = clients.get(target)
                if sock:
                    send(sock, f"[SERVER → {target}] {msg}")
                    print(f"  → PM → {target}: {msg}")
                    audit("SERVER_PM", detail=f"to={target} msg={msg!r}")
                else:
                    print(f"  [!] User '{target}' not found.")
            else:
                print("  Usage: /msg <username> <message>")

        # ── /alert ────────────────────────────────────────────────────
        elif cmd.startswith("/alert "):
            parts = cmd.split(" ", 2)
            if len(parts) == 3:
                target, msg = parts[1], parts[2]
                with _state_lock:
                    sock = clients.get(target)
                if sock:
                    send(sock, f"⚠️  [ALERT from SERVER] {msg}")
                    print(red(f"  🚨 Alert → {target}: {msg}"))
                    audit("ALERT", detail=f"to={target} msg={msg!r}", severity="MEDIUM")
                else:
                    print(f"  [!] '{target}' not found.")
            else:
                print("  Usage: /alert <username> <message>")

        # ── /users ────────────────────────────────────────────────────
        elif cmd == "/users":
            print(list_users_detailed())

        # ── /inspect <user> ───────────────────────────────────────────
        elif cmd.startswith("/inspect "):
            target = cmd.split(" ", 1)[1].strip()
            with _state_lock:
                connected = target in clients
            role     = "ADMIN"    if target in admins    else "user"
            fstatus  = "FROZEN"   if target in frozen    else \
                       "SHADOWED" if target in shadowed  else \
                       "WATCHED"  if target in watchlist else "active"
            ip_addr  = client_addrs.get(target, ("unknown",))[0]
            msg_cnt  = sum(1 for m in msg_history if m["sender"] == target)
            thr_cnt  = sum(1 for m in msg_history
                           if m["sender"] == target and "THREAT" in m.get("type", ""))
            exec_cnt = sum(1 for m in msg_history
                           if m["sender"] == target and "EXEC" in m.get("type", ""))
            notes    = operator_notes.get(target, [])
            print(f"""
  ┌─ User Profile: {bold(target)}
  │  Connected     : {'Yes' if connected else 'No'}
  │  IP Address    : {ip_addr}
  │  Role          : {role}
  │  Status        : {fstatus}
  │  Msgs in log   : {msg_cnt}
  │  Threats caught: {thr_cnt}
  │  Exec attempts : {exec_cnt}
  │  Notes         : {len(notes)} entries
  └────────────────────────────────""")

        # ── /kick ─────────────────────────────────────────────────────
        elif cmd.startswith("/kick "):
            target = cmd.split(" ", 1)[1].strip()
            with _state_lock:
                sock = clients.get(target)
            if sock:
                send(sock, "[SERVER] You have been kicked.")
                sock.close()
                remove_client(target)
                broadcast(f"[SERVER] {target} was removed by the operator.")
                audit("KICK", detail=f"user={target}", severity="MEDIUM")
                print(f"  → Kicked {target}.")
            else:
                print(f"  [!] '{target}' not found.")

        # ── /freeze / /unfreeze ───────────────────────────────────────
        elif cmd.startswith("/freeze "):
            target = cmd.split(" ", 1)[1].strip()
            with _state_lock:
                if target not in clients:
                    print(f"  [!] '{target}' not connected.")
                    continue
                frozen.add(target)
                sock = clients[target]
            send(sock, "[SERVER] Your messages are being reviewed.")
            audit("FREEZE", detail=f"user={target}", severity="LOW")
            print(f"  → {target} frozen.")

        elif cmd.startswith("/unfreeze "):
            target = cmd.split(" ", 1)[1].strip()
            frozen.discard(target)
            with _state_lock:
                sock = clients.get(target)
            if sock:
                send(sock, "[SERVER] Your messaging has been restored.")
            audit("UNFREEZE", detail=f"user={target}")
            print(f"  → {target} unfrozen.")

        # ── /shadow / /unshadow ───────────────────────────────────────
        elif cmd.startswith("/shadow "):
            target = cmd.split(" ", 1)[1].strip()
            with _state_lock:
                if target not in clients:
                    print(f"  [!] '{target}' not connected.")
                    continue
            shadowed.add(target)
            # Do NOT notify the user — that defeats the purpose
            audit("SHADOW", detail=f"user={target}", severity="LOW")
            print(yellow(f"  → {target} shadow-muted (they don't know)."))

        elif cmd.startswith("/unshadow "):
            target = cmd.split(" ", 1)[1].strip()
            shadowed.discard(target)
            audit("UNSHADOW", detail=f"user={target}")
            print(f"  → {target} shadow removed.")

        # ── /rename <old> <new> ───────────────────────────────────────
        elif cmd.startswith("/rename "):
            parts = cmd.split()
            if len(parts) < 3:
                print("  Usage: /rename <old_username> <new_username>")
                continue
            old_name, new_name = parts[1], parts[2]
            if not re.match(r'^[A-Za-z0-9_]{1,20}$', new_name):
                print("  [!] Invalid new username.")
                continue
            with _state_lock:
                if old_name not in clients:
                    print(f"  [!] '{old_name}' not connected.")
                    continue
                if new_name in clients:
                    print(f"  [!] '{new_name}' already taken.")
                    continue
                sock              = clients.pop(old_name)
                clients[new_name] = sock
                addr              = client_addrs.pop(old_name, None)
                if addr:
                    client_addrs[new_name] = addr
            # Move role/state data
            if old_name in admins:   admins.discard(old_name);   admins.add(new_name)
            if old_name in frozen:   frozen.discard(old_name);   frozen.add(new_name)
            if old_name in shadowed: shadowed.discard(old_name); shadowed.add(new_name)
            if old_name in watchlist:watchlist.discard(old_name);watchlist.add(new_name)
            send(sock, f"[SERVER] Your username has been changed to '{new_name}'.")
            broadcast(f"[SERVER] {old_name} is now known as {new_name}.", exclude=new_name)
            audit("RENAME", detail=f"old={old_name} new={new_name}")
            print(f"  → Renamed {old_name} → {new_name}.")

        # ── /tempban <user> <seconds> ─────────────────────────────────
        elif cmd.startswith("/tempban "):
            parts = cmd.split()
            if len(parts) < 3:
                print("  Usage: /tempban <username> <seconds>")
                continue
            target = parts[1]
            try:
                secs = int(parts[2])
            except ValueError:
                print("  [!] Seconds must be a number.")
                continue
            with _state_lock:
                sock = clients.get(target)
                addr = client_addrs.get(target)
            if not sock or not addr:
                print(f"  [!] '{target}' not connected.")
                continue
            ip = addr[0]
            send(sock, f"[SERVER] You have been temporarily banned for {secs}s.")
            sock.close()
            remove_client(target)
            apply_tempban(ip, secs)
            save_banned_ips()
            broadcast(f"[SERVER] {target} has been temporarily removed.")
            audit("TEMPBAN", detail=f"user={target} ip={ip} secs={secs}",
                  severity="MEDIUM")
            print(yellow(f"  → {target} ({ip}) temp-banned for {secs}s."))

        # ── /banip / /unbanip / /bans ─────────────────────────────────
        elif cmd.startswith("/banip "):
            ip = cmd.split(" ", 1)[1].strip()
            banned_ips.add(ip)
            save_banned_ips()
            # Kick any current connections from this IP
            with _state_lock:
                victims = [u for u, a in client_addrs.items() if a[0] == ip]
            for v in victims:
                with _state_lock:
                    sock = clients.get(v)
                if sock:
                    send(sock, "[SERVER] Your IP has been banned.")
                    sock.close()
                    remove_client(v)
            audit("BAN_IP", detail=f"ip={ip}", severity="HIGH")
            print(red(f"  → IP {ip} banned. {len(victims)} client(s) kicked."))

        elif cmd.startswith("/unbanip "):
            ip = cmd.split(" ", 1)[1].strip()
            banned_ips.discard(ip)
            tempban_ends.pop(ip, None)
            save_banned_ips()
            audit("UNBAN_IP", detail=f"ip={ip}")
            print(green(f"  → IP {ip} unbanned."))

        elif cmd == "/bans":
            if not banned_ips:
                print("  No IPs currently banned.")
            else:
                print(f"  Banned IPs ({len(banned_ips)}):")
                for ip in sorted(banned_ips):
                    remaining = ""
                    if ip in tempban_ends:
                        secs = int(tempban_ends[ip] - time.time())
                        remaining = f" (temp — {max(0, secs)}s left)"
                    print(f"    • {ip}{remaining}")

        # ── /notes <user> <text> ──────────────────────────────────────
        elif cmd.startswith("/notes "):
            rest = cmd[7:].strip()
            parts = rest.split(" ", 1)
            if len(parts) < 2:
                print("  Usage: /notes <username> <note text>")
                continue
            target, note = parts[0], parts[1]
            ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
            entry = f"[{ts}] {note}"
            operator_notes.setdefault(target, []).append(entry)
            save_notes()
            audit("NOTE_ADDED", detail=f"user={target} note={note!r}")
            print(f"  → Note added for {target}.")

        # ── /shownotes <user> ─────────────────────────────────────────
        elif cmd.startswith("/shownotes "):
            target = cmd.split(" ", 1)[1].strip()
            notes  = operator_notes.get(target, [])
            if not notes:
                print(f"  No notes for {target}.")
            else:
                print(f"\n  ── Notes for {target} ({len(notes)}) ──")
                for n in notes:
                    print(f"  {n}")
                print()

        # ── /admin / /revoke ──────────────────────────────────────────
        elif cmd.startswith("/admin "):
            target = cmd.split(" ", 1)[1].strip()
            with _state_lock:
                connected = target in clients
                sock      = clients.get(target)
            if not connected:
                print(f"  [!] '{target}' not connected.")
                continue
            admins.add(target)
            if sock:
                send(sock, "[SERVER] ★ You have been granted ADMIN privileges.\n"
                           "[SERVER]   Use /exec <user> \"<cmd>\" for remote shell.")
            broadcast(f"[SERVER] {target} is now an admin.", exclude=target)
            audit("ADMIN_GRANT", detail=f"user={target}")
            print(green(f"  → {target} promoted to admin. ★"))

        elif cmd.startswith("/revoke "):
            target = cmd.split(" ", 1)[1].strip()
            if target not in admins:
                print(f"  [!] '{target}' is not an admin.")
                continue
            admins.discard(target)
            with _state_lock:
                sock = clients.get(target)
            if sock:
                send(sock, "[SERVER] Your admin privileges have been revoked.")
            audit("ADMIN_REVOKE", detail=f"user={target}")
            print(f"  → Admin revoked from {target}.")

        elif cmd == "/admins":
            with _state_lock:
                online_admins = [a for a in admins if a in clients]
            print("  Admins online: " + (", ".join(online_admins) or "none"))

        # ── /sniff ────────────────────────────────────────────────────
        elif cmd == "/sniff":
            spy_mode[0] = not spy_mode[0]
            state = "ENABLED 👁" if spy_mode[0] else "DISABLED 🔒"
            print(yellow(f"  → Spy mode: {state}"))
            audit("SPY_TOGGLE", detail=f"state={state}")

        # ── /history [n] ──────────────────────────────────────────────
        elif cmd.startswith("/history"):
            parts = cmd.split()
            try:
                n = int(parts[1]) if len(parts) > 1 else 20
            except ValueError:
                n = 20
            n = min(n, len(msg_history))
            if n == 0:
                print("  No messages in history buffer yet.")
            else:
                print(f"\n  ── Last {n} intercepted messages ──────────────")
                for m in list(msg_history)[-n:]:
                    if m["type"] == "PRIVATE":
                        print(f"  [{m['ts']}] [{m['type']:<18}] "
                              f"{m['sender']} → {m['recipient']}: {m['text']}")
                    else:
                        print(f"  [{m['ts']}] [{m['type']:<18}] "
                              f"{m['sender']}: {m['text']}")
                print()

        # ── /search <keyword> ─────────────────────────────────────────
        elif cmd.startswith("/search "):
            keyword = cmd[8:].strip().lower()
            matches = [m for m in msg_history if keyword in m["text"].lower()]
            if not matches:
                print(f"  No messages matching '{keyword}'.")
            else:
                print(f"\n  ── {len(matches)} match(es) for '{keyword}' ──")
                for m in matches[-50:]:
                    print(f"  [{m['ts']}] {m['sender']}: {m['text']}")
                print()

        # ── /watch / /unwatch / /watchlist ────────────────────────────
        elif cmd.startswith("/watch "):
            target = cmd.split(" ", 1)[1].strip()
            watchlist.add(target)
            audit("WATCH_ADD", detail=f"user={target}")
            print(yellow(f"  → {target} added to watchlist."))

        elif cmd.startswith("/unwatch "):
            target = cmd.split(" ", 1)[1].strip()
            watchlist.discard(target)
            audit("WATCH_REMOVE", detail=f"user={target}")
            print(f"  → {target} removed from watchlist.")

        elif cmd == "/watchlist":
            if not watchlist:
                print("  Watchlist is empty.")
            else:
                print("  Watched users: " + ", ".join(watchlist))

        # ── /stats ────────────────────────────────────────────────────
        elif cmd == "/stats":
            with _state_lock:
                online     = len(clients)
                admin_cnt  = len([a for a in admins  if a in clients])
                frozen_cnt = len(frozen)
                shadow_cnt = len(shadowed)
            uptime_s   = int(time.time() - server_start)
            h, r = divmod(uptime_s, 3600)
            m, s = divmod(r, 60)
            print(f"""
  ┌─ Server Statistics ──────────────────────────────────
  │  Uptime               : {h:02d}:{m:02d}:{s:02d}
  │  Clients online       : {online}  (admins: {admin_cnt}, frozen: {frozen_cnt}, shadow: {shadow_cnt})
  │  Total connections    : {stats['connections_total']}
  │  Broadcast messages   : {stats['total_messages']}
  │  Private messages     : {stats['private_messages']}
  │  /exec attempts       : {stats['exec_attempts']}
  │  Blocked / downgraded : {stats['blocked_attempts']}
  │  Remote shell runs    : {stats['remote_shell_runs']}
  │  Threats caught       : {stats['threats_caught']}
  │  Rate violations      : {stats['rate_violations']}
  │  History buffer       : {len(msg_history)}/{MAX_HISTORY}
  │  Spy mode             : {'ON 👁' if spy_mode[0] else 'OFF 🔒'}
  │  Banned IPs           : {len(banned_ips)}
  │  Watchlist            : {len(watchlist)} user(s)
  └──────────────────────────────────────────────────────""")

        # ── /log ──────────────────────────────────────────────────────
        elif cmd == "/log":
            try:
                with open(AUDIT_LOG, "r", encoding="utf-8") as f:
                    lines = f.readlines()
                tail = lines[-20:]
                print(f"\n  ── Last {len(tail)} audit log entries ──")
                for line in tail:
                    print("  " + line.rstrip())
                print()
            except FileNotFoundError:
                print("  [!] Audit log not created yet.")

        # ── /export ───────────────────────────────────────────────────
        elif cmd == "/export":
            print(export_audit_csv())

        # ── /uptime ───────────────────────────────────────────────────
        elif cmd == "/uptime":
            uptime_s = int(time.time() - server_start)
            h, r = divmod(uptime_s, 3600)
            m, s = divmod(r, 60)
            active = len(clients)
            print(f"  Uptime: {h:02d}h {m:02d}m {s:02d}s | Clients: {active} | "
                  f"Threats: {stats['threats_caught']} | "
                  f"Messages: {stats['total_messages']}")

        # ── /ping <user> ──────────────────────────────────────────────
        elif cmd.startswith("/ping "):
            target = cmd.split(" ", 1)[1].strip()
            print(f"  Pinging {target}...")
            result = ping_client(target)
            print(f"  {result}")
            audit("PING", detail=f"target={target} result={result!r}")

        # ── ★ /rshell <user> "<cmd>" ──────────────────────────────────
        elif cmd.startswith("/rshell "):
            rest = cmd[8:].strip()
            try:
                tokens = shlex.split(rest)
            except ValueError:
                tokens = rest.split(" ", 1)

            if len(tokens) < 2:
                print('  Usage: /rshell <username> "<command>"')
                continue

            tu        = tokens[0]
            ci        = " ".join(tokens[1:])

            with _state_lock:
                connected = tu in clients

            if not connected:
                print(f"  [!] '{tu}' not connected.")
                continue

            print(cyan(f'  ⚙  Sending to {tu}: $ {ci}'))
            audit("RSHELL_OP", detail=f"target={tu} cmd={ci!r}", severity="HIGH")
            stats["remote_shell_runs"] += 1

            def _op_rshell(tu=tu, ci=ci):
                out = remote_exec_on_client(tu, ci, timeout=RSHELL_TIMEOUT)
                _print_rshell_box(tu, ci, out)
                audit("RSHELL_DONE",
                      detail=f"target={tu} cmd={ci!r} out={out[:120]!r}")

            threading.Thread(target=_op_rshell, daemon=True).start()

        # ── /reload ───────────────────────────────────────────────────
        elif cmd == "/reload":
            global CONF, RATE_BURST, RATE_WINDOW, RSHELL_TIMEOUT
            CONF          = load_config()
            RATE_BURST    = int(CONF["rate_limit_burst"])
            RATE_WINDOW   = int(CONF["rate_limit_window"])
            RSHELL_TIMEOUT= int(CONF["rshell_timeout"])
            motd[0]       = CONF["motd"]
            print(green("  → server_config.ini reloaded."))
            audit("CONFIG_RELOAD")

        # ── /quit [seconds] ───────────────────────────────────────────
        elif cmd.startswith("/quit"):
            parts = cmd.split()
            delay = 5
            try:
                if len(parts) > 1:
                    delay = int(parts[1])
            except ValueError:
                pass
            if delay > 0:
                broadcast(f"[SERVER] ⚠ Server shutting down in {delay}s. Goodbye!")
                print(f"  Waiting {delay}s before shutdown...")
                time.sleep(delay)
            else:
                broadcast("[SERVER] Server shutting down now. Goodbye!")
            audit("SHUTDOWN")
            print("[Server] Shutting down.")
            os._exit(0)

        elif cmd == "/help":
            print(CONSOLE_HELP)

        else:
            print("  Unknown command. Type /help.")


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    load_banned_ips()
    load_notes()

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((SERVER_HOST, SERVER_PORT))
    server_sock.listen(MAX_CLIENTS)

    uptime_start = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print(f"""
╔══════════════════════════════════════════════════════════════════╗
║   SecureChat Server v4.0 — port {SERVER_PORT:<5}                        ║
║   ★ Remote Shell  : /rshell <user> "<cmd>"                       ║
║   ★ Rate limiting : {RATE_BURST} msgs / {RATE_WINDOW}s per user               ║
║   ★ Threat IDS    : {len(THREAT_PATTERNS)} patterns loaded                      ║
║   Spy mode     : {'ON 👁' if spy_mode[0] else 'OFF 🔒':<48}║
║   Audit log    : {AUDIT_LOG:<48}║
║   Started      : {uptime_start:<48}║
║   Type /help for the full command list.                          ║
╚══════════════════════════════════════════════════════════════════╝
""")

    audit("STARTUP", detail=f"port={SERVER_PORT} max_clients={MAX_CLIENTS}")

    console_thread = threading.Thread(target=server_console, daemon=True)
    console_thread.start()

    try:
        while True:
            conn, addr = server_sock.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()
    except KeyboardInterrupt:
        print("\n[Server] Interrupted. Shutting down.")
        audit("SHUTDOWN", detail="KeyboardInterrupt")
    finally:
        broadcast("[SERVER] Server is going offline.")
        server_sock.close()


if __name__ == "__main__":
    main()