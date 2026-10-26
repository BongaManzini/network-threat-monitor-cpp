#include "Platform.hpp"
#include "ThreatDetector.hpp"
#include "Sniffer.hpp"
#include "AegisConnector.hpp"

#include <iostream>
#include <fstream>
#include <iomanip>
#include <chrono>
#include <csignal>
#include <atomic>
#include <memory>

static std::atomic<bool> g_keepRunning{true};
static std::atomic<bool> g_showPacketFeed{true};

void signalHandler(int) {
    g_keepRunning = false;
}

void printBanner(const std::string& osName, const std::string& serverUrl, bool connected, size_t blacklistCount) {
    std::cout << Platform::Color::Cyan() << Platform::Color::Bold();
    std::cout << "========================================================================\n";
    std::cout << "   📡  AEGIS: C++ NETWORK MONITOR & SENSOR NODE (v2.0)\n";
    std::cout << "========================================================================\n";
    std::cout << Platform::Color::Reset();
    std::cout << " [•] Operating System : " << Platform::Color::White() << Platform::Color::Bold() << osName << Platform::Color::Reset() << "\n";
    std::cout << " [•] Self-Healing Net : " << serverUrl << " ";
    if (connected) {
        std::cout << Platform::Color::Green() << Platform::Color::Bold() << "[CONNECTED - AUTO-HEAL ONLINE]" << Platform::Color::Reset() << "\n";
    } else {
        std::cout << Platform::Color::Yellow() << Platform::Color::Bold() << "[STANDBY / LOCAL CACHE]" << Platform::Color::Reset() << "\n";
    }
    std::cout << " [•] Active Blacklist : " << blacklistCount << " IP rules synchronized\n";
    std::cout << " [•] Audit Log Path   : " << Platform::getLogFilePath() << "\n";
    std::cout << Platform::Color::Cyan();
    std::cout << "========================================================================\n" << Platform::Color::Reset();
}

void printBandwidthGraph(const std::unordered_map<std::string, size_t>& bwMap) {
    std::cout << Platform::Color::Cyan() << "\n--- Bandwidth Usage Graph (Source IP -> Volume) ---\n" << Platform::Color::Reset();
    if (bwMap.empty()) {
        std::cout << "  (No traffic recorded yet)\n";
        return;
    }
    for (const auto& entry : bwMap) {
        size_t kb = entry.second / 1024;
        std::cout << "  " << std::left << std::setw(18) << entry.first << " : "
                  << std::right << std::setw(6) << kb << " KB ";
        int blocks = static_cast<int>(kb / 10);
        if (blocks > 40) blocks = 40;
        std::cout << Platform::Color::Green();
        for (int i = 0; i < blocks; ++i) std::cout << "█";
        std::cout << Platform::Color::Reset() << "\n";
    }
    std::cout << "\n";
}

int main(int argc, char* argv[]) {
    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);

    Platform::enableVTMode();
    Platform::initSockets();

    std::string serverUrl = "http://127.0.0.1:5000";
    std::string ifaceName = "";
    bool forceSimulate = false;
    bool headless = false;

    // Parse command line arguments
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if ((arg == "--server" || arg == "-s") && i + 1 < argc) {
            serverUrl = argv[++i];
        } else if ((arg == "--interface" || arg == "-i") && i + 1 < argc) {
            ifaceName = argv[++i];
        } else if (arg == "--simulate" || arg == "-m") {
            forceSimulate = true;
        } else if (arg == "--headless" || arg == "-d") {
            headless = true;
        } else if (arg == "--help" || arg == "-h") {
            std::cout << "Usage: " << argv[0] << " [options]\n"
                      << "  -s, --server <url>      AEGIS Self-Healing REST URL (default: http://127.0.0.1:5000)\n"
                      << "  -i, --interface <name>  Network interface name to sniff\n"
                      << "  -m, --simulate          Force simulated traffic generator (unprivileged test mode)\n"
                      << "  -d, --headless          Run in background non-interactive daemon mode\n"
                      << "  -h, --help              Show this help menu\n";
            return 0;
        }
    }

    std::string osName = Platform::getOSName();
    AegisConnector aegis(serverUrl);
    ThreatDetector detector;
    Sniffer sniffer;

    // Probe connection to AEGIS Self-Healing Network
    bool connected = aegis.checkHealth();

    // Synchronize initial blacklists from AEGIS firewall
    std::vector<std::string> blockedIPs;
    if (connected && aegis.syncBlacklist(blockedIPs)) {
        detector.syncBlacklist(blockedIPs);
    }

    printBanner(osName, serverUrl, connected, detector.getBlacklistedIPs().size());

    // Select interface
    auto interfaces = Sniffer::getAvailableInterfaces();
    if (ifaceName.empty() && !interfaces.empty()) {
        ifaceName = interfaces[0].name;
    }

    std::ofstream logFile(Platform::getLogFilePath(), std::ios::app);

    // Setup packet processing callback
    auto onPacket = [&](const PacketData& pkt) {
        // Inspect for threats
        auto alerts = detector.inspectPacket(pkt);

        if (!alerts.empty()) {
            for (const auto& alert : alerts) {
                // Colored console alert
                std::cout << "\n" << Platform::Color::Red() << Platform::Color::Bold()
                          << " [🚨 INTRUSION DETECTED] " << alert.threat_type << Platform::Color::Reset() << "\n"
                          << "  [•] Attacker IP : " << Platform::Color::Yellow() << alert.source_ip << Platform::Color::Reset() << "\n"
                          << "  [•] Target Node : " << alert.target_ip << "\n"
                          << "  [•] Description : " << alert.description << "\n";

                // Log to file
                if (logFile.is_open()) {
                    logFile << "[THREAT][" << alert.threat_type << "] " 
                            << alert.source_ip << " -> " << alert.target_ip 
                            << " (" << alert.description << ")" << std::endl;
                }

                // Send to AEGIS Self-Healing Network for autonomous remediation
                std::string healingResult;
                bool dispatched = aegis.sendAlert(alert, healingResult);
                if (dispatched) {
                    std::cout << "  " << Platform::Color::Green() << Platform::Color::Bold()
                              << "[✓ AEGIS REMEDIATED] " << healingResult << Platform::Color::Reset() << "\n\n";
                    // Add to local blacklist to prevent repeated processing
                    detector.addBlacklistedIP(alert.source_ip);
                } else {
                    std::cout << "  " << Platform::Color::Dim()
                              << "[!] Alert saved locally (AEGIS connection offline)" << Platform::Color::Reset() << "\n\n";
                }
            }
        } else if (g_showPacketFeed) {
            std::cout << Platform::Color::Dim() << "[IPv4] " 
                      << pkt.src_ip << ":" << pkt.src_port << " -> " 
                      << pkt.dst_ip << ":" << pkt.dst_port << " (" 
                      << (pkt.protocol == 6 ? "TCP" : pkt.protocol == 17 ? "UDP" : "RAW") 
                      << ", " << pkt.length << "B)" 
                      << Platform::Color::Reset() << "\n";
        }
    };

    CaptureMode capMode = forceSimulate ? CaptureMode::SIMULATED : CaptureMode::LIVE;
    sniffer.start(ifaceName, capMode, onPacket);

    std::cout << Platform::Color::Green() << "[INFO] Sniffing active on: " 
              << ifaceName << " (" << (capMode == CaptureMode::LIVE ? "Live Capture" : "Simulated Traffic Engine") << ")" 
              << Platform::Color::Reset() << "\n";

    // Launch background thread to send periodic heartbeats to AEGIS
    auto startTime = std::chrono::steady_clock::now();
    std::thread heartbeatThread([&]() {
        size_t lastBytes = 0;
        auto lastTime = std::chrono::steady_clock::now();

        while (g_keepRunning) {
            Platform::sleepMs(2000); // 2-second interval
            auto now = std::chrono::steady_clock::now();
            double dt = std::chrono::duration<double>(now - lastTime).count();
            double uptime = std::chrono::duration<double>(now - startTime).count();

            size_t currentBytes = sniffer.getTotalBytes();
            double kbps = 0.0;
            if (dt > 0.0) {
                kbps = (currentBytes >= lastBytes) ? ((currentBytes - lastBytes) / 1024.0) / dt : 0.0;
            }
            lastBytes = currentBytes;
            lastTime = now;

            std::string monId = "cpp-sensor-" + osName;
            aegis.sendTelemetry(monId, ifaceName, 
                                sniffer.getTotalPackets(), 
                                sniffer.getTotalBytes(), 
                                detector.getTotalThreatsDetected(), 
                                kbps, uptime);

            // Periodically sync blacklist (every ~10s)
            static int syncCounter = 0;
            if (++syncCounter >= 5) {
                syncCounter = 0;
                std::vector<std::string> latestBlocked;
                if (aegis.syncBlacklist(latestBlocked)) {
                    detector.syncBlacklist(latestBlocked);
                }
            }
        }
    });

    if (headless) {
        std::cout << "[INFO] Running in headless daemon mode. Press Ctrl+C to terminate.\n";
        while (g_keepRunning) {
            Platform::sleepMs(500);
        }
    } else {
        std::cout << "\nInteractive Commands: "
                  << Platform::Color::Yellow()
                  << "[1] Toggle Feed  [2] Threats  [3] Bandwidth Graph  [4] Sync Rules  [5] Test Port Scan  [6] Test MITM  [q] Quit\n"
                  << Platform::Color::Reset();

        while (g_keepRunning) {
            std::string input;
            if (!std::getline(std::cin, input)) {
                break;
            }
            if (input == "q" || input == "Q" || input == "exit") {
                break;
            } else if (input == "1") {
                g_showPacketFeed = !g_showPacketFeed;
                std::cout << "[INFO] Live packet feed " << (g_showPacketFeed ? "ENABLED" : "MUTED") << "\n";
            } else if (input == "2") {
                auto threats = detector.getThreats();
                std::cout << Platform::Color::Cyan() << "\n=== Detected Threats Audit (" << threats.size() << ") ===\n" << Platform::Color::Reset();
                for (const auto& t : threats) {
                    std::cout << "  - [" << t.threat_type << "] " << t.source_ip << " -> " << t.target_ip 
                              << " (" << t.description << ")\n";
                }
                std::cout << "\n";
            } else if (input == "3") {
                printBandwidthGraph(detector.getBandwidthStats());
            } else if (input == "4") {
                std::vector<std::string> latest;
                if (aegis.syncBlacklist(latest)) {
                    detector.syncBlacklist(latest);
                    std::cout << Platform::Color::Green() << "[INFO] Synced " << latest.size() 
                              << " firewall rules from AEGIS successfully.\n" << Platform::Color::Reset();
                } else {
                    std::cout << Platform::Color::Red() << "[WARN] Failed to connect to AEGIS to sync rules.\n" << Platform::Color::Reset();
                }
            } else if (input == "5") {
                std::cout << "[TEST] Triggering simulated port scan intrusion...\n";
                sniffer.injectThreat("port_scan", "198.51.100.42");
            } else if (input == "6") {
                std::cout << "[TEST] Triggering simulated MITM ARP spoof surge...\n";
                sniffer.injectThreat("mitm_attack", "192.168.1.188");
            }
        }
    }

    // Graceful cleanup
    g_keepRunning = false;
    sniffer.stop();
    if (heartbeatThread.joinable()) {
        heartbeatThread.join();
    }
    Platform::cleanupSockets();
    logFile.close();

    std::cout << Platform::Color::Green() << "\n[INFO] AEGIS C++ Network Monitor safely stopped.\n" << Platform::Color::Reset();
    return 0;
}
