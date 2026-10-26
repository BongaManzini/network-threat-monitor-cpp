#pragma once

#include "ThreatDetector.hpp"
#include <string>
#include <vector>
#include <functional>
#include <thread>
#include <atomic>

struct NetworkInterface {
    std::string name;
    std::string description;
    std::string ip_address;
    bool is_up = true;
    bool is_loopback = false;
};

enum class CaptureMode {
    LIVE,
    SIMULATED
};

class Sniffer {
public:
    using PacketCallback = std::function<void(const PacketData&)>;

    Sniffer();
    ~Sniffer();

    // Query available network adapters on the local OS
    static std::vector<NetworkInterface> getAvailableInterfaces();

    // Start sniffing on the specified interface
    bool start(const std::string& ifaceName, CaptureMode mode, PacketCallback callback);

    // Stop active sniffing
    void stop();

    // Inject a specific threat traffic pattern immediately (for testing / demo)
    void injectThreat(const std::string& threatType, const std::string& attackerIP = "");

    // Telemetry accessors
    bool isRunning() const { return m_running; }
    CaptureMode getMode() const { return m_mode; }
    std::string getActiveInterface() const { return m_activeInterface; }
    size_t getTotalPackets() const { return m_totalPackets; }
    size_t getTotalBytes() const { return m_totalBytes; }

private:
    std::atomic<bool> m_running{false};
    CaptureMode m_mode = CaptureMode::SIMULATED;
    std::string m_activeInterface;
    PacketCallback m_callback;
    std::thread m_workerThread;

    std::atomic<size_t> m_totalPackets{0};
    std::atomic<size_t> m_totalBytes{0};

    void runLiveCapture(const std::string& iface);
    void runSimulatedCapture();
};
