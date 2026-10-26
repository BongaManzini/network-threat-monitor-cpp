#include "AegisConnector.hpp"
#include "Platform.hpp"
#include <iostream>
#include <sstream>
#include <cstring>
#include <regex>

AegisConnector::AegisConnector(const std::string& baseUrl)
    : m_baseUrl(baseUrl)
{
    parseUrl(baseUrl);
    Platform::initSockets();
}

AegisConnector::~AegisConnector() {
    // Sockets cleaned up on application exit
}

void AegisConnector::parseUrl(const std::string& url) {
    // Basic parser for http://host:port
    std::string clean = url;
    size_t proto_pos = clean.find("://");
    if (proto_pos != std::string::npos) {
        clean = clean.substr(proto_pos + 3);
    }
    
    // Strip trailing slash
    if (!clean.empty() && clean.back() == '/') {
        clean.pop_back();
    }

    size_t colon_pos = clean.find(':');
    if (colon_pos != std::string::npos) {
        m_host = clean.substr(0, colon_pos);
        try {
            m_port = std::stoi(clean.substr(colon_pos + 1));
        } catch (...) {
            m_port = 5000;
        }
    } else {
        m_host = clean;
        m_port = 5000;
    }

    if (m_host.empty() || m_host == "0.0.0.0") {
        m_host = "127.0.0.1";
    }
}

bool AegisConnector::checkHealth() {
    int status = 0;
    std::string body;
    bool ok = executeHttpRequest("GET", "/health", "", status, body);
    m_lastConnected = (ok && status == 200);
    return m_lastConnected;
}

bool AegisConnector::sendTelemetry(const std::string& monitor_id, 
                                   const std::string& active_iface,
                                   size_t packets,
                                   size_t bytes,
                                   size_t threats,
                                   double bandwidth_kbps,
                                   double uptime_seconds)
{
    std::ostringstream ss;
    ss << "{"
       << "\"monitor_id\":\"" << monitor_id << "\","
       << "\"platform\":\"" << Platform::getOSName() << "\","
       << "\"active_interface\":\"" << active_iface << "\","
       << "\"packets_captured\":" << packets << ","
       << "\"bytes_captured\":" << bytes << ","
       << "\"threats_detected\":" << threats << ","
       << "\"bandwidth_kbps\":" << bandwidth_kbps << ","
       << "\"uptime_seconds\":" << uptime_seconds
       << "}";

    int status = 0;
    std::string body;
    bool ok = executeHttpRequest("POST", "/api/integrations/cpp-monitor/telemetry", ss.str(), status, body);
    m_lastConnected = (ok && status == 200);
    return m_lastConnected;
}

bool AegisConnector::sendAlert(const ThreatAlert& alert, std::string& outSummary) {
    std::ostringstream ss;
    ss << "{"
       << "\"monitor_id\":\"cpp-monitor-" << Platform::getOSName() << "\","
       << "\"platform\":\"" << Platform::getOSName() << "\","
       << "\"threat_type\":\"" << alert.threat_type << "\","
       << "\"severity\":\"" << alert.severity << "\","
       << "\"source_ip\":\"" << alert.source_ip << "\","
       << "\"target_ip\":\"" << alert.target_ip << "\","
       << "\"description\":\"" << alert.description << "\""
       << "}";

    int status = 0;
    std::string body;
    bool ok = executeHttpRequest("POST", "/api/integrations/cpp-monitor/alert", ss.str(), status, body);
    m_lastConnected = (ok && status == 200);

    if (ok && status == 200) {
        // Quick extraction of remediation actions executed
        if (body.find("\"self_healed\":true") != std::string::npos || body.find("\"success\":true") != std::string::npos) {
            outSummary = "Autonomous Self-Healing Executed: Attacker IP dropped in host firewall";
        } else {
            outSummary = "Alert recorded in AEGIS Incident Register";
        }
        return true;
    } else {
        outSummary = "HTTP " + std::to_string(status) + ": Connection failed or rejected";
        return false;
    }
}

bool AegisConnector::syncBlacklist(std::vector<std::string>& outBlockedIPs) {
    int status = 0;
    std::string body;
    bool ok = executeHttpRequest("GET", "/api/integrations/cpp-monitor/sync-rules", "", status, body);
    m_lastConnected = (ok && status == 200);

    if (!ok || status != 200) {
        return false;
    }

    // Extract blocked_ips array: "blocked_ips": ["1.2.3.4", "8.8.8.8"]
    size_t array_pos = body.find("\"blocked_ips\":");
    if (array_pos == std::string::npos) {
        return true;
    }

    size_t start = body.find('[', array_pos);
    size_t end = body.find(']', start);
    if (start != std::string::npos && end != std::string::npos && end > start) {
        std::string list_str = body.substr(start + 1, end - start - 1);
        std::regex ip_regex("\"([0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+)\"");
        std::sregex_iterator it(list_str.begin(), list_str.end(), ip_regex);
        std::sregex_iterator reg_end;
        while (it != reg_end) {
            outBlockedIPs.push_back((*it)[1].str());
            ++it;
        }
    }

    return true;
}

bool AegisConnector::executeHttpRequest(const std::string& method,
                                        const std::string& path,
                                        const std::string& jsonBody,
                                        int& outStatusCode,
                                        std::string& outResponseBody)
{
    outStatusCode = 0;
    outResponseBody.clear();

    struct addrinfo hints = {};
    hints.ai_family = AF_INET; // IPv4
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    struct addrinfo* result = nullptr;
    std::string portStr = std::to_string(m_port);

    if (getaddrinfo(m_host.c_str(), portStr.c_str(), &hints, &result) != 0 || !result) {
        return false;
    }

    socket_t sock = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (IS_INVALID_SOCKET(sock)) {
        freeaddrinfo(result);
        return false;
    }

    // Set 2.5 second timeout for connect and receive
#ifdef _WIN32
    DWORD timeout = 2500;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));
#else
    struct timeval tv;
    tv.tv_sec = 2;
    tv.tv_usec = 500000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif

    if (connect(sock, result->ai_addr, static_cast<int>(result->ai_addrlen)) == SOCKET_ERROR) {
        CLOSESOCKET(sock);
        freeaddrinfo(result);
        return false;
    }
    freeaddrinfo(result);

    // Build HTTP/1.1 Request
    std::ostringstream req;
    req << method << " " << path << " HTTP/1.1\r\n";
    req << "Host: " << m_host << ":" << m_port << "\r\n";
    req << "User-Agent: AegisCPPNetworkMonitor/2.0 (" << Platform::getOSName() << ")\r\n";
    req << "Accept: application/json\r\n";
    if (!jsonBody.empty()) {
        req << "Content-Type: application/json\r\n";
        req << "Content-Length: " << jsonBody.length() << "\r\n";
    }
    req << "Connection: close\r\n\r\n";
    if (!jsonBody.empty()) {
        req << jsonBody;
    }

    std::string reqStr = req.str();
    int sent = send(sock, reqStr.c_str(), static_cast<int>(reqStr.length()), 0);
    if (sent <= 0) {
        CLOSESOCKET(sock);
        return false;
    }

    // Read response
    char buffer[4096];
    std::string fullResponse;
    int bytesRead = 0;
    while ((bytesRead = recv(sock, buffer, sizeof(buffer) - 1, 0)) > 0) {
        buffer[bytesRead] = '\0';
        fullResponse.append(buffer, bytesRead);
    }
    CLOSESOCKET(sock);

    if (fullResponse.empty()) {
        return false;
    }

    // Parse status line: HTTP/1.1 200 OK
    size_t firstLineEnd = fullResponse.find("\r\n");
    if (firstLineEnd != std::string::npos) {
        std::string statusLine = fullResponse.substr(0, firstLineEnd);
        size_t sp1 = statusLine.find(' ');
        if (sp1 != std::string::npos) {
            size_t sp2 = statusLine.find(' ', sp1 + 1);
            std::string codeStr = statusLine.substr(sp1 + 1, (sp2 != std::string::npos) ? (sp2 - sp1 - 1) : std::string::npos);
            try {
                outStatusCode = std::stoi(codeStr);
            } catch (...) {
                outStatusCode = 0;
            }
        }
    }

    // Parse body after headers (\r\n\r\n)
    size_t bodyPos = fullResponse.find("\r\n\r\n");
    if (bodyPos != std::string::npos) {
        outResponseBody = fullResponse.substr(bodyPos + 4);
    } else {
        outResponseBody = fullResponse;
    }

    return (outStatusCode >= 200 && outStatusCode < 300);
}
