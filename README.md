# 📡 Network Threat Monitor (C++ / WinPcap)

A high-performance C++ Windows desktop network sniffer and threat detection utility using WinPcap/Npcap and native Win32 GUI controls.

---

## ✨ Features

- **Live Packet Sniffing**: Captures raw IPv4 traffic directly from selected network adapters.
- **Threat Detection Heuristics**:
  - Instant IP blacklisting alerts
  - Rapid-fire port scanning detection (sliding window timestamp tracking)
  - Suspected Man-in-the-Middle (MITM) traffic spikes
  - Bandwidth consumption anomalies
- **Live GUI HUD**: Native Win32 desktop application with live RichEdit colored audit log, bandwidth distribution charts, and interface selection dropdown.

---

## 🛠️ Build Requirements

- **Platform**: Windows 10/11
- **Toolchain**: MSVC / Visual Studio or MinGW (Code::Blocks)
- **Libraries**: `wpcap.lib`, `Packet.lib`, `ws2_32.lib`, `Comctl32.lib`
- **Driver**: Npcap or WinPcap driver installed in WinPcap API-compatible mode
