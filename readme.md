# Ez-Paqet 🚀

Ez-Paqet is a collection of automated installation scripts for **Paqet**, a high-performance network tunneling tool designed to work even in restrictive network environments. These scripts simplify the setup process on Linux servers and clients, handling dependencies, configuration, and system services automatically.

## 📖 What is Paqet?

Paqet (pronounced "packet") is a tool that allows you to create a secure, encrypted "tunnel" between two computers over the internet. It is particularly useful for bypassing network restrictions, censorship, or firewalls by routing traffic through a remote server.:

- **The Server (Exit Node):** A VPS in a "free" or unrestricted network.
- **The Client (Bridge Node):** A VPS in a restricted network that connects to the Server.

Once connected, the Client creates a local SOCKS5 proxy. Any traffic sent to this proxy is tunneled to the Server and out to the internet, bypassing local restrictions.

---

## 🛠️ Prerequisites

To establish a functional tunnel, you need **two separate Linux servers**:

1. **Remote Server (Free Network):** A VPS located in an unrestricted region (e.g., US, Europe).
2. **Local/Bridge Server (Restricted Network):** A VPS located in the restricted region where you want to bypass filtering.

Each server must have:

- **Root Access:** Administrative privileges (ability to use `sudo`).
- **Supported OS:** Ubuntu, Debian, CentOS, or Fedora.
- **Internet Access:** To download the installation scripts and binaries.

---

## 🚀 Quick Setup (Recommended)

The easiest way to get started is using the **Unified Installer**. This script will ask you whether you want to set up a Server or a Client and do the rest for you.

Run this command on your Linux terminal:

```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/rm-rfd/ez-paqet/main/install.sh)"
```

_If you don't have `curl`, you can use `wget` instead:_

```bash
sudo bash -c "$(wget -qO- https://raw.githubusercontent.com/rm-rfd/ez-paqet/main/install.sh)"
```

---

## 🖥️ Manual Installation

If you prefer to install a specific component directly, you can use the individual scripts.

### 1. Server Setup

The server is the "exit point" of your tunnel. Install this on a VPS or a machine with an unrestricted internet connection.

```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/rm-rfd/ez-paqet/main/install-server.sh)"
```

- **What it does:** Installs the Paqet binary, generates a unique encryption key, and starts the service.
- **Important:** Note down the **Server IP**, **Port**, and **Encryption Key** shown at the end. You will need these for the client.

### 2. Client Setup

The client is the "entry point". Install this on the device that needs to bypass restrictions.

```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/rm-rfd/ez-paqet/main/install-client.sh)"
```

- **What it does:** Installs dependencies, asks for the Server IP and Key, and sets up a SOCKS5 proxy.
  > **Note on Proxy:** If your network is highly restricted and you cannot even download the Paqet binary or dependencies, the script will prompt you to enter an HTTP/HTTPS proxy. This allows the installer to "pass through" the initial restrictions using a temporary proxy that you know works.- **Result:** It creates a local proxy at `127.0.0.1:1080`.

---

## 🔍 How to Use the Tunnel

After the client is installed and running:

1. **Browser Setup:** Configure your browser (like Chrome or Firefox) to use a **SOCKS5 Proxy** at address `127.0.0.1` and port `1080`.
2. **Terminal Test:** You can verify it's working by running:
   ```bash
   curl -v https://httpbin.org/ip --proxy socks5h://127.0.0.1:1080
   ```
   If successful, the IP address returned should be your **Server's IP**.

---

## 🛡️ Advanced: Integration with 3x-ui (Xray Panel)

You can use Paqet as a "bridge" for your Xray panel (like [3x-ui](https://github.com/MHSanaei/3x-ui)). This allows you to route your VLESS/VMess traffic through the Paqet tunnel to a VPS in a free internet region.

### 1. Ensure Paqet is Running

Make sure your Paqet client is running on your restricted VPS and listening on the SOCKS5 port (default: `127.0.0.1:1080`).

### 2. Install panel on your restricted VPS if you haven't already.

### 3. Configure 3x-ui Outbound

You need to add a "Socks" outbound in your panel to connect to the local Paqet port.

1. Open your **3x-ui Panel**.
2. Go to **Settings** (or Panel Settings).
3. Look for **Xray Configuration** (or Config Template).
4. Find the `"outbounds": [...]` section.
5. Add the following object to the **top** of the outbounds list (so it becomes the default route):

```json
{
  "protocol": "socks",
  "settings": {
    "servers": [
      {
        "address": "127.0.0.1",
        "port": 1080,
        "users": []
      }
    ]
  },
  "tag": "paqet-proxy"
}
```

> **Note:** If you already have a `freedom` (direct) outbound, ensure this new SOCKS block is placed **above** it so that all traffic goes through the private tunnel automatically.

### 4. Verify Routing

Once you save the configuration and restart the Xray service via the panel:

1. **Inbound Path:** A user connects to your restricted VPS using VLESS/VMess.
2. **Xray Processing:** Xray receives the traffic.
3. **Outbound Path:** Xray forwards it to the **Default Outbound** -> `127.0.0.1:1080` (Paqet).
4. **Tunneling:** Paqet wraps the traffic and sends it to your **Remote Server** in the free region.

---

## ⚙️ Managing the Service

The scripts set up Paqet as a background service so it starts automatically when your computer turns on.

| Action           | Command (Client)                 | Command (Server)          |
| :--------------- | :------------------------------- | :------------------------ |
| **Check Status** | `systemctl status paqet-client`  | `systemctl status paqet`  |
| **View Logs**    | `journalctl -u paqet-client -f`  | `journalctl -u paqet -f`  |
| **Restart**      | `systemctl restart paqet-client` | `systemctl restart paqet` |
| **Stop**         | `systemctl stop paqet-client`    | `systemctl stop paqet`    |

---

## ⚠️ Important Security Notes

- **Keep your Key Secret:** Anyone with your Server IP, Port, and Key can use your tunnel.
- **Firewall:** Ensure the port you chose (default `54321`) is open in your server's firewall (like UFW or AWS Security Groups).
- **Updates:** These scripts use a specific version of Paqet. To update, you may need to run the installer again or check for new versions of the scripts.

---

## 📄 License

This project is for educational purposes. Please ensure your use of tunneling tools complies with your local laws and terms of service.
