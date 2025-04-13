# Secure_Comm_IMS Setup & Execution Guide

This document outlines the steps required to install, configure, and run the Secure Communication IMS (Instant Messaging System) using multiple IP interfaces on a single machine.

---

## 🛠️ Setup Instructions

### 1. Install Required Packages

Run the following commands to update your system and install Python and dependencies:

```bash
sudo apt update
sudo apt install python3
sudo apt install python3-pip
pip3 install -r requirements.txt
```

---

## 🧪 Setup Dummy Interface (for Multi-Client on Same Machine)

To simulate two clients on the same machine (e.g., Raspberry Pi), you need to create a dummy IP address/interface. This allows each client to bind to a unique IP.

### 1. Get Your Current Interface and IP

```bash
ifconfig
```

**Example Output (simplified):**

```text
eth0: inet 10.10.96.10  netmask 255.255.255.0
lo:   inet 127.0.0.1    netmask 255.0.0.0
```

### 2. Create a Dummy Interface

```bash
sudo ip addr add 10.10.96.11/24 dev eth0 label eth0:1
```

### 3. Verify the Interface Exists

```bash
ifconfig
```

You should now see:

```text
eth0:   inet 10.10.96.10
eth0:1: inet 10.10.96.11
```

---

## ⚙️ Configure Server IP

Edit the `config.json` file and update the `server_ip` to match your interface IP (e.g., `10.10.96.10`):

```json
{
  "server_ip": "10.10.96.10",
  "server_port": 9999,
  "client_port": 12000,
  "log_level": "INFO"
}
```

---

## 🚀 Run the Server

Start the server with:

```bash
python3 server.py
```

🔐 Use password `123` when prompted (for demo/testing). Password is kept simple for demo purpose.

---

## 💻 Run the Clients

Open **two terminal windows** and run one client in each, binding to a different interface:

```bash
# Terminal 1
python3 clients.py -i eth0:1

# Terminal 2
python3 clients.py -i eth0
```

---

## 👤 User Login (Preconfigured)

When prompted, log in using one of the following users (pre-loaded on the server):

| Username | Password |
|----------|----------|
| alice    | 123      |
| bob      | 1234     |
| martin   | 4321     |

⚠️ **Note**: There is *no signup flow* — only login is supported for demo purposes.

---

## 🧼 Cleanup (optional)

To remove the dummy interface:

```bash
sudo ip addr del 10.10.96.11/24 dev eth0
```

---

## 📢 Notes

- Ensure all IP addresses are within the same subnet (`10.10.96.0/24`).
- This setup is ideal for local testing on Raspberry Pi or virtual machines.
- The dummy IP setup allows full-duplex secure client-to-client messaging on the same machine.

---

Happy Hacking! 🔐
