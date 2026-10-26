# 📡 AEGIS C++ Network Threat Monitor & Sensor Node

> **Cross-Platform C++17 Network Packet Sniffer, Intrusion Detection Sensor, and Autonomous Self-Healing Link for Linux and Windows.**

---

## ✨ Features

- **Cross-Platform Core**: Natively compiles and runs on both **Linux** (GCC, Clang, Make, CMake) and **Windows** (MSVC, MinGW, Code::Blocks).
- **Direct Integration with AEGIS Self-Healing Network**:
  - Automatically establishes an HTTP/REST socket link with the Python Self-Healing Network (`http://localhost:5000`).
  - Streams live telemetry: packet counters, bandwidth throughput (KB/s), detected anomalies, and heartbeat status.
  - Dispatches instant intrusion alerts to AEGIS to trigger **sub-second autonomous self-healing** (firewall drop, ARP neighbor purging, device quarantine).
  - Continuously synchronizes active firewall blacklists from AEGIS back into the C++ sniffer.
- **Intrusion Detection Heuristics**:
  - **Dynamic Blacklist Matching**: Real-time packet filtering against active firewall drop rules.
  - **Sliding-Window Port Scan Detection**: High-frequency SYN/probe sweeps tracked across time intervals.
  - **Suspected Man-in-the-Middle (MITM)**: Detects ARP poisoning bursts and abnormal traffic redirection.
  - **Bandwidth Consumption & Exfiltration**: Real-time bandwidth tracking with threshold triggers.
- **Dual Capture Modes**:
  - **Live Capture**: Uses raw sockets (`AF_PACKET` / raw IP on Linux, WinSock / Npcap on Windows) for live network traffic.
  - **Simulated Test Engine**: Built-in synthetic traffic generator enabling instant end-to-end testing in unprivileged environments (containers, non-root users) without requiring specialized kernel drivers.
- **User Interfaces**:
  - **Interactive CLI HUD**: High-performance colorized terminal monitor with real-time ASCII bandwidth graphs and hotkeys.
  - **Legacy Win32 GUI**: Native Windows desktop GUI preserved in `src/win32_gui.cpp` with RichEdit colored audit log.

---

## 🛠️ Build Instructions

### On Linux (Ubuntu, Debian, Fedora, Arch)

#### Using Make:
```bash
cd Legacy-CPP-Network-Monitor
make
```
The binary will be compiled to `bin/network_monitor`.

To run the automated C++ unit tests:
```bash
make test
```

#### Using CMake:
```bash
cd Legacy-CPP-Network-Monitor
cmake -B build
cmake --build build
ctest --test-dir build
```

---

### On Windows (MSVC, MinGW, Code::Blocks)

#### Using MinGW / GCC:
```cmd
cd Legacy-CPP-Network-Monitor
make
```

#### Using CMake & Visual Studio:
```cmd
cd Legacy-CPP-Network-Monitor
cmake -B build
cmake --build build --config Release
```

#### Using Code::Blocks:
Open `Network Monitor App.cbp` in Code::Blocks and click **Build and Run** (`F9`).

---

## 🚀 Running the Monitor

### 1. Connect to Live AEGIS Self-Healing Network
Start the AEGIS Self-Healing server first:
```bash
cd ../Self-Healing-Network
./venv/bin/python src/main.py
```

Then in a second terminal, start the C++ Network Monitor:
```bash
cd Legacy-CPP-Network-Monitor
./bin/network_monitor
```

### 2. Command-Line Options
```bash
./bin/network_monitor --help

Options:
  -s, --server <url>      AEGIS Self-Healing REST URL (default: http://127.0.0.1:5000)
  -i, --interface <name>  Network interface name to sniff (e.g. eth0, wlan0)
  -m, --simulate          Run with simulated traffic generator (unprivileged test mode)
  -d, --headless          Run in background non-interactive daemon mode
  -h, --help              Show help menu
```

### 3. Interactive Terminal Hotkeys
When running in interactive mode, use these hotkeys:
- `1` : Toggle live packet scrolling feed ON/OFF
- `2` : Show detected threats audit log
- `3` : Display real-time ASCII bandwidth usage graph
- `4` : Force synchronize active firewall blacklists from AEGIS
- `5` : Inject test simulated port scan sweep
- `6` : Inject test simulated MITM ARP spoof surge
- `q` : Exit gracefully

---

## 🔗 Autonomous Self-Healing Integration Architecture

```
+------------------------------------+        REST / HTTP (JSON)        +----------------------------------------+
|    C++ Network Monitor Sensor      |  =============================>  |   AEGIS Self-Healing Network (Python)  |
|  (Linux & Windows Packet Sniffer)  |  POST /api/integrations/cpp-     |    (PolicyEngine & Cross-Platform OS)  |
|                                    |       monitor/alert              |                                        |
|  - Packet Capture (Live / Sim)     |                                  |  1. Ingests threat signal              |
|  - Sliding-Window Port Scan        |  <=============================  |  2. Evaluates security policy          |
|  - MITM & ARP Surge Detector       |   JSON Remediation Confirmation  |  3. Executes autonomous self-healing:  |
|  - Real-time Bandwidth Tracking    |                                  |     • Drops attacker IP in iptables    |
|                                    |  -----------------------------   |       or netsh advfirewall             |
|  - Background Telemetry Thread     |   POST /telemetry (Heartbeat)    |     • Purges poisoned ARP cache        |
|  - Dynamic In-Memory Blacklist     |  ----------------------------->  |     • Updates Health Score (0-100%)    |
|                                    |                                  |                                        |
|                                    |  <-----------------------------  |  4. Streams live telemetry to Web HUD  |
|                                    |   GET /sync-rules (Firewall)     |     at http://localhost:5000           |
+------------------------------------+                                  +----------------------------------------+
```

---

## 🧪 Unit Testing

Unit test suite covers heuristic sliding-window algorithms, blacklist sync, and REST connector serialization:

```bash
cd Legacy-CPP-Network-Monitor
make test
```

Expected Output:
```
=== Running Threat Detector Unit Test ===
[TEST] Running test_blacklist...
  ✓ test_blacklist PASSED
[TEST] Running test_port_scan...
  ✓ test_port_scan PASSED
[TEST] Running test_mitm_detection...
  ✓ test_mitm_detection PASSED
[TEST] Running test_bandwidth_anomaly...
  ✓ test_bandwidth_anomaly PASSED
All ThreatDetector Tests PASSED (4/4)

=== Running Aegis Connector Unit Test ===
[TEST] Running test_url_parsing...
  ✓ test_url_parsing PASSED
All AegisConnector Tests PASSED
```

---

## 📄 License

MIT License. Copyright (c) 2024–2026 AEGIS Contributors.
