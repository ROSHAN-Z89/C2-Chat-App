# C2 Chat App  
**Command-and-Control TCP Chat System**

---

## Overview

C2 Chat App is an advanced TCP-based client-server chat system designed for **educational cybersecurity and red team simulation purposes**. It mimics a command-and-control (C2) style communication model, allowing centralized control, monitoring, and interaction with multiple connected clients.

Use at your own Risk.

---

## Features

### Communication
- Multi-client TCP server
- Real-time messaging system
- Public and private chat support
- Username-based identification

### Command & Control Capabilities
- Centralized command execution on clients
- Remote shell functionality (admin-controlled)
- Output retrieval from client systems
- Asynchronous command handling

### Administrative Controls
- Role-based access (Admin/User)
- User moderation:
  - Kick users
  - Freeze messaging
  - Shadow mute (ghost mode)
  - Rename users
- Watchlist system for monitoring suspicious users

### Security & Monitoring
- Built-in **Intrusion Detection System (IDS)**
- Threat pattern recognition (commands, payloads, keywords)
- Rate limiting to prevent spam/flood attacks
- IP banning and temporary bans
- Connection tracking per IP

### Logging & Auditing
- Full audit logging (plaintext or JSON)
- Message history buffer
- Export logs to CSV
- Real-time server statistics

### Operator Tools
- Spy mode (intercept all messages)
- Keyword search in chat history
- Operator notes system
- Ping system to measure client latency

### Configuration
- Configurable via `server_config.ini`
- Hot reload without restarting server
- Persistent storage for:
  - Banned IPs
  - Operator notes

---
## Installation

### Requirements
- Python 3.8 or higher

### Clone the Repository
```bash
git clone https://github.com/your-username/c2-chat-app.git
cd c2-chat-app
```
### Usage

Start the Server
```bash
python server.py
```
Start the Client
```bash
python client.py
```
Connect to a remote server
```bash
python client.py <host> <port>
```

## Server Console Commands

### Communication
- `/broadcast <msg>` — Send message to all clients  
- `/wall <msg>` — Set message of the day  
- `/msg <user> <msg>` — Private message  

### User Management
- `/kick <user>` — Disconnect user  
- `/freeze <user>` — Silent mute  
- `/shadow <user>` — Ghost mute  
- `/rename <old> <new>` — Rename user  
- `/tempban <user> <seconds>` — Temporary ban  

### Admin Management
- `/admin <user>` — Grant admin privileges  
- `/revoke <user>` — Remove admin privileges  

### Monitoring
- `/sniff` — Toggle spy mode  
- `/history [n]` — View message history  
- `/search <keyword>` — Search logs  
- `/watch <user>` — Add user to watchlist  

### Remote Shell
- `/rshell <user> "<cmd>"` — Execute command on client  

### System
- `/stats` — View server statistics  
- `/log` — View audit logs  
- `/export` — Export logs to CSV  
- `/reload` — Reload configuration  
- `/uptime` — Show server uptime  
- `/quit` — Shutdown server

  ---

## Client Commands

| Command | Description |
|--------|------------|
| `/users` | List connected users |
| `/msg <user> <text>` | Send private message |
| `/admins` | List online admins |
| `/status` | Show your role/status |
| `/help` | Display help menu |
| `/quit` | Disconnect from server |

### Admin Command

| Command | Description |
|--------|------------|
| `/exec <user> "<cmd>"` | Execute command on target client |

