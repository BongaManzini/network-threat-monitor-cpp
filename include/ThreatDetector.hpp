#pragma once

#include <string>
#include <vector>
#include <unordered_set>
#include <unordered_map>
#include <chrono>
#include <mutex>
#include <optional>
#include <cstdint>

struct PacketData {
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    uint8_t protocol = 0; // 6 = TCP, 17 = UDP, 1 = ICMP
    size_t length = 0;
    std::chrono::system_clock::time_point timestamp = std::chrono::system_clock::now();
};

struct ThreatAlert {
    std::string threat_type;   // "port_scan", "mitm_attack", "blacklisted_ip", "data_exfiltration", "malware"
    std::string severity;      // "low", "medium", "high", "critical"
    std::string source_ip;
    std::string target_ip;
    std::string description;
    int packet_count = 1;
    uint64_t timestamp = 0;
    std::string protocol = "IPv4";
};

class ThreatDetector {
public:
    ThreatDetector();

    // Blacklist management (thread-safe)
    bool isBlacklisted(const std::string& ip) const;
    void addBlacklistedIP(const std::string& ip);
    void removeBlacklistedIP(const std::string& ip);
    void syncBlacklist(const std::vector<std::string>& ips);
    std::vector<std::string> getBlacklistedIPs() const;

    // Inspect incoming packet against heuristic detectors
    // Returns a list of any triggered alerts
    std::vector<ThreatAlert> inspectPacket(const PacketData& packet);

    // Threat history & telemetry inspection
    std::vector<ThreatAlert> getThreats() const;
    std::unordered_map<std::string, size_t> getBandwidthStats() const;
    size_t getTotalThreatsDetected() const;
    void clearThreats();

    // Configurable thresholds
    void setPortScanThreshold(size_t packets, int windowSeconds);
    void setBandwidthLimit(size_t bytesLimit);
    void setMitmThreshold(int packetThreshold);

private:
    mutable std::mutex m_mutex;

    // Detection heuristics state
    std::unordered_set<std::string> m_blacklistedIPs;
    std::unordered_map<std::string, std::vector<std::chrono::steady_clock::time_point>> m_portScanMap;
    std::unordered_map<std::string, size_t> m_bandwidthMap;
    std::unordered_map<std::string, int> m_mitmCount;
    std::vector<ThreatAlert> m_detectedThreats;

    // Threshold configurations
    size_t m_portScanPackets = 10;
    std::chrono::seconds m_portScanWindow{5};
    size_t m_bandwidthLimitBytes = 10 * 1024 * 1024; // 10MB
    int m_mitmThreshold = 50;
    size_t m_totalThreatCount = 0;
};
