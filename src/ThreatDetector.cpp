#include "ThreatDetector.hpp"
#include <ctime>
#include <algorithm>

ThreatDetector::ThreatDetector() {
    // Default baseline blacklisted endpoints
    m_blacklistedIPs = { "1.2.3.4", "8.8.8.8", "198.51.100.42", "203.0.113.99" };
}

bool ThreatDetector::isBlacklisted(const std::string& ip) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_blacklistedIPs.find(ip) != m_blacklistedIPs.end();
}

void ThreatDetector::addBlacklistedIP(const std::string& ip) {
    if (ip.empty() || ip == "127.0.0.1" || ip == "0.0.0.0") return;
    std::lock_guard<std::mutex> lock(m_mutex);
    m_blacklistedIPs.insert(ip);
}

void ThreatDetector::removeBlacklistedIP(const std::string& ip) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_blacklistedIPs.erase(ip);
}

void ThreatDetector::syncBlacklist(const std::vector<std::string>& ips) {
    std::lock_guard<std::mutex> lock(m_mutex);
    for (const auto& ip : ips) {
        if (!ip.empty()) {
            m_blacklistedIPs.insert(ip);
        }
    }
}

std::vector<std::string> ThreatDetector::getBlacklistedIPs() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return std::vector<std::string>(m_blacklistedIPs.begin(), m_blacklistedIPs.end());
}

std::vector<ThreatAlert> ThreatDetector::inspectPacket(const PacketData& packet) {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<ThreatAlert> triggeredAlerts;
    uint64_t now_epoch = static_cast<uint64_t>(std::time(nullptr));

    const std::string& src = packet.src_ip;
    const std::string& dst = packet.dst_ip;

    // 1. Blacklisted IP Detection
    if (m_blacklistedIPs.count(src) || m_blacklistedIPs.count(dst)) {
        ThreatAlert alert;
        alert.threat_type = "blacklisted_ip";
        alert.severity = "high";
        alert.source_ip = m_blacklistedIPs.count(src) ? src : dst;
        alert.target_ip = m_blacklistedIPs.count(src) ? dst : src;
        alert.description = "Communication detected with blacklisted IP: " + alert.source_ip;
        alert.packet_count = 1;
        alert.timestamp = now_epoch;
        alert.protocol = (packet.protocol == 6) ? "TCP" : (packet.protocol == 17) ? "UDP" : "IPv4";
        triggeredAlerts.push_back(alert);
    }

    // 2. Rapid-Fire Port Scan Detection (Sliding Window)
    if (!src.empty() && src != "127.0.0.1") {
        auto now = std::chrono::steady_clock::now();
        auto& timestamps = m_portScanMap[src];
        timestamps.push_back(now);

        // Prune older entries
        while (!timestamps.empty() && (now - timestamps.front()) > m_portScanWindow) {
            timestamps.erase(timestamps.begin());
        }

        if (timestamps.size() >= m_portScanPackets) {
            ThreatAlert alert;
            alert.threat_type = "port_scan";
            alert.severity = "high";
            alert.source_ip = src;
            alert.target_ip = dst;
            alert.description = "Rapid reconnaissance port scan sweep detected (" + 
                                std::to_string(timestamps.size()) + " packets in sliding window)";
            alert.packet_count = static_cast<int>(timestamps.size());
            alert.timestamp = now_epoch;
            alert.protocol = "TCP";
            triggeredAlerts.push_back(alert);

            // Reset tracker window so we don't spam on every single subsequent packet
            timestamps.clear();
        }
    }

    // 3. Bandwidth Consumption / Data Exfiltration Anomaly
    if (!src.empty()) {
        m_bandwidthMap[src] += (packet.length > 0 ? packet.length : 1500);
        if (m_bandwidthMap[src] > m_bandwidthLimitBytes) {
            ThreatAlert alert;
            alert.threat_type = "data_exfiltration";
            alert.severity = "high";
            alert.source_ip = src;
            alert.target_ip = dst;
            alert.description = "High bandwidth consumption threshold exceeded (>10MB volume)";
            alert.packet_count = 1;
            alert.timestamp = now_epoch;
            alert.protocol = "IPv4";
            triggeredAlerts.push_back(alert);

            // Reset bandwidth accumulator
            m_bandwidthMap[src] = 0;
        }
    }

    // 4. Suspected MITM / Traffic Spike Detection
    if (!dst.empty() && dst != "127.0.0.1" && dst != "255.255.255.255") {
        m_mitmCount[dst]++;
        if (m_mitmCount[dst] > m_mitmThreshold) {
            ThreatAlert alert;
            alert.threat_type = "mitm_attack";
            alert.severity = "high";
            alert.source_ip = src;
            alert.target_ip = dst;
            alert.description = "Abnormal packet surge indicating active ARP Poisoning / MITM attack";
            alert.packet_count = m_mitmCount[dst];
            alert.timestamp = now_epoch;
            alert.protocol = "ARP/IPv4";
            triggeredAlerts.push_back(alert);

            m_mitmCount[dst] = 0;
        }
    }

    // Append to history and total count
    for (const auto& a : triggeredAlerts) {
        m_detectedThreats.push_back(a);
        m_totalThreatCount++;
        if (m_detectedThreats.size() > 200) {
            m_detectedThreats.erase(m_detectedThreats.begin());
        }
    }

    return triggeredAlerts;
}

std::vector<ThreatAlert> ThreatDetector::getThreats() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_detectedThreats;
}

std::unordered_map<std::string, size_t> ThreatDetector::getBandwidthStats() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_bandwidthMap;
}

size_t ThreatDetector::getTotalThreatsDetected() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_totalThreatCount;
}

void ThreatDetector::clearThreats() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_detectedThreats.clear();
}

void ThreatDetector::setPortScanThreshold(size_t packets, int windowSeconds) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_portScanPackets = packets;
    m_portScanWindow = std::chrono::seconds(windowSeconds);
}

void ThreatDetector::setBandwidthLimit(size_t bytesLimit) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_bandwidthLimitBytes = bytesLimit;
}

void ThreatDetector::setMitmThreshold(int packetThreshold) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_mitmThreshold = packetThreshold;
}
