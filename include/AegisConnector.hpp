#pragma once

#include "ThreatDetector.hpp"
#include <string>
#include <vector>
#include <memory>

class AegisConnector {
public:
    explicit AegisConnector(const std::string& baseUrl = "http://127.0.0.1:5000");
    ~AegisConnector();

    // Health probe to verify connection to AEGIS Self-Healing Network
    bool checkHealth();

    // Transmit periodic heartbeat and telemetry counters
    bool sendTelemetry(const std::string& monitor_id, 
                       const std::string& active_iface,
                       size_t packets,
                       size_t bytes,
                       size_t threats,
                       double bandwidth_kbps,
                       double uptime_seconds);

    // Dispatch threat alert to trigger autonomous self-healing remediation
    bool sendAlert(const ThreatAlert& alert, std::string& outSummary);

    // Fetch synchronized firewall blacklist rules from AEGIS
    bool syncBlacklist(std::vector<std::string>& outBlockedIPs);

    // Accessors
    std::string getHost() const { return m_host; }
    int getPort() const { return m_port; }
    bool isConnected() const { return m_lastConnected; }

private:
    std::string m_baseUrl;
    std::string m_host;
    int m_port = 5000;
    bool m_lastConnected = false;

    void parseUrl(const std::string& url);

    // Low-level cross-platform HTTP 1.1 request dispatcher
    bool executeHttpRequest(const std::string& method,
                            const std::string& path,
                            const std::string& jsonBody,
                            int& outStatusCode,
                            std::string& outResponseBody);
};
