# PacketSense-CPP
---
A network packet analysis and manipulation tool built with C++ and libpcap.

PacketSense-CPP is a network utility designed to capture, log, and actively manage TCP connections on a Linux system.

---
### ⚠️ Security & Disclaimer
This tool is intended **strictly for educational purposes, security research, and controlled testing environments only.**
The user assumes all liability and responsibility for the use of this software.

**User Responsibility**: You are solely responsible for ensuring you have the necessary **legal permissions and authorization** before running this tool on any network or system.

**Restricted Environments**: This software must only be used in environments that you **own or have explicit, documented permission to test.**

**Prohibition of Misuse**: Using this tool to disrupt networks or gain **unauthorized access** is strictly prohibited and may constitute illegal activity.

**No Liability**: The developers and contributors of this project **assume no liability** for any damages, data loss, or legal consequences resulting from the misuse or unauthorized operation of this software.

**Acceptance of Risk**: By using **PacketSense-CPP**, you **fully accept all risks and responsibility** for its actions and outcomes.

---
## ✨ Features
**Packet Capture**: Uses **libpcap** to capture raw network packets from a specified interface.

**Packet Logging**: Analyzed packet data is stored in a structured **SQLite** database (`ps-cpp.db`).

**Active Connection Rejection (TCP Kill)**: Can actively reject TCP connections to specified IP addresses and ports by **injecting forged RST (Reset)** packets.

**Logging:** file-based logging via **spdlog**.

**Configurable:** All parameters (interfaces, filters, rejection settings) managed via `config.conf`.


---
## 🛠️ Prerequisites
**Platform:** Linux  
**Dependencies:**
- C++17 or higher
- `libpcap` (for packet capture)
- `sqlite3` (for data storage)
- `spdlog` (for logging)
- `build-essential` (g++, make, etc.)

---
## 🚀 Getting Started
Follow these steps to build and run PacketSense-CPP on your system.

1. Build the Executable
   Use the provided shell script to compile the source code.

   ```bash
   chmod +x compile.sh
   compile.sh
   ...
   ls -l ps-cpp
   ```

   A file named `ps-cpp` should now exist in the directory.


2. Configure Settings
   Edit the `config.conf` file to define your desired network interface, filter rules, and rejection settings.

   |Item|Description|
   |----|-----------|
   |capture_interface|The network interface to monitor (e.g., eth0).|
   |promiscuous_mode|Set to true to capture all traffic on the network.|
   |capture_filter|A **BPF (Berkeley Packet Filter)** string (e.g., tcp and port 80).|
   |reject|Set to true to enable TCP connection rejection (kill) feature.|
   |reject_ips|Comma-separated list of target IP addresses for rejection.|
   |reject_ports|Comma-separated list of target ports for rejection.|

   **Example** config.conf :
   ```
   capture_interface = eth0
   promiscuous_mode = false
   capture_filter = tcp and port 22
   reject = true
   reject_ips = 192.168.67.7, 192.168.67.8
   reject_ports = 22
   ```


3. Run the Program
   Due to the use of **libpcap** for raw packet capture and injection, the program **must be executed with root privileges.**
   ```bash
   ps-cpp -c config.conf
   ```


4. Verify Database Creation
   After running:
   ```bash
   ls -l ps-cpp.db
   ls -l logs/
   ```
   `ps-cpp.db` — SQLite database containing captured packet data
   `ps-cpp.log` — runtime log produced by spdlog (located in ./logs/ relative to where the program was started)

5. Stop the Program
   To stop the program at any time, simply press:
   ```
   [ctrl] + [c]
   ```

---
## 💻 Tech Stack
Language: C++

Packet Capture: libpcap

Database: SQLite3

Logging: spdlog
