## Misc

git clone https://github.com/worai/security.git

rust b --release

## Don't work on termux

❌ Packet Sniffing – Needs pcap and raw sockets, which require root.
❌ ARP Spoofing – Needs raw socket access.
❌ MITM Attacks – Needs privileged network control.
❌ Network Interface Monitoring – Needs /proc/net/dev, which is restricted.

## Staying safe at work

### **Security-Related Commands to Avoid Running at Work** 🚨
Running certain security commands at work **can trigger alarms** with your IT department, **violate company policies**, or even **get you into legal trouble** depending on your company’s rules and jurisdiction.

### **🚫 High-Risk (DON’T RUN)**
These **commands can be seen as hacking or reconnaissance** activities. Running them at work **without authorization** could result in disciplinary action or job termination.

| **Command** | **Why It's Risky** |
|------------|-----------------|
| `nmap` | Port scanning **can trigger IDS alerts** and be interpreted as an attack. |
| `tcpdump` / `wireshark` | **Packet sniffing** is highly restricted; it can expose **confidential data**. |
| `airmon-ng` / `airodump-ng` | **Wi-Fi scanning and sniffing** could be seen as **hacking** company networks. |
| `hydra` / `john` / `hashcat` | **Password cracking** is illegal without explicit permission. |
| `ettercap` / `dsniff` | **MITM (Man-in-the-Middle) attacks** are highly illegal and detectable. |
| `arp-scan` | Scanning for devices **can be seen as network reconnaissance**. |
| `metasploit` | **Penetration testing tools** require prior approval. |
| `nc -lvp` (Netcat in listening mode) | Can be seen as **backdoor activity**. |
| `ping -f` | Flood pinging **can be seen as a DoS attack**. |

🚨 **Anything that scans the network, captures traffic, or attempts exploitation is a major red flag at work.**

---

### **✅ Low-Risk (Generally Safe)**
These are usually safe to run **if they are part of your work responsibilities**, **or for troubleshooting.** However, it’s best to **check company policy** before using them.

| **Command** | **Why It's Generally OK** |
|------------|-----------------|
| `whois example.com` | Basic **domain lookup** is harmless. |
| `nslookup` / `dig` | Checking **DNS records** is normal for troubleshooting. |
| `ifconfig` / `ip a` | Checking **your own** network interfaces is fine. |
| `netstat -tulnp` | Checking **open ports on your machine** is normal. |
| `traceroute` / `mtr` | **Network debugging** (e.g., detecting connectivity issues). |
| `uptime` / `top` | Monitoring **system performance** is fine. |
| `lsof -i` | Checking **which processes are using network connections** is useful. |

---

### **💡 How to Stay Safe**
1. **Check Company Policy**  
   - Read your **IT security guidelines** before running security tools.
   - Some companies allow **scanning and monitoring on authorized networks**.

2. **Use a Dedicated Lab or VM**  
   - If you need to experiment, do it **on a separate machine**, not the corporate network.

3. **Ask for Permission**  
   - If your job involves **security research**, get approval before running **scanning, monitoring, or penetration testing tools**.

4. **Avoid Running Security Tools on VPN**  
   - Some companies **monitor VPN traffic** and may flag security tools.

5. **Log Everything (If Authorized)**  
   - If you are in IT security, logging **your own scans** can **prove intent** if questioned.

---

### **Final Thoughts**
- **If you’re in doubt, don’t run it at work.**
- **If a command interacts with the network beyond your machine, it’s risky.**
- **Stick to diagnostic tools unless you have explicit permission.**

Would you like help setting up a **safe lab environment** for security testing? 🚀