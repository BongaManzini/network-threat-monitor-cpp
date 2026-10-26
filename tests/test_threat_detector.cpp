#include "ThreatDetector.hpp"
#include <cassert>
#include <iostream>
#include <thread>
#include <chrono>

void test_blacklist() {
    std::cout << "[TEST] Running test_blacklist...\n";
    ThreatDetector detector;
    assert(detector.isBlacklisted("1.2.3.4"));
    assert(detector.isBlacklisted("8.8.8.8"));
    assert(!detector.isBlacklisted("10.0.0.1"));

    detector.addBlacklistedIP("10.0.0.1");
    assert(detector.isBlacklisted("10.0.0.1"));

    std::vector<std::string> syncList = {"192.168.1.99", "172.16.0.5"};
    detector.syncBlacklist(syncList);
    assert(detector.isBlacklisted("192.168.1.99"));
    assert(detector.isBlacklisted("172.16.0.5"));

    PacketData pkt;
    pkt.src_ip = "192.168.1.99";
    pkt.dst_ip = "192.168.1.15";
    auto alerts = detector.inspectPacket(pkt);
    assert(!alerts.empty());
    assert(alerts[0].threat_type == "blacklisted_ip");
    std::cout << "  ✓ test_blacklist PASSED\n";
}

void test_port_scan() {
    std::cout << "[TEST] Running test_port_scan...\n";
    ThreatDetector detector;
    detector.setPortScanThreshold(10, 5);

    std::string scannerIP = "198.51.100.200";
    std::vector<ThreatAlert> allAlerts;

    // Send 9 packets: should NOT trigger yet
    for (int i = 0; i < 9; ++i) {
        PacketData pkt;
        pkt.src_ip = scannerIP;
        pkt.dst_ip = "192.168.1.55";
        pkt.dst_port = 1000 + i;
        pkt.protocol = 6;
        pkt.length = 64;
        auto a = detector.inspectPacket(pkt);
        if (!a.empty()) allAlerts.insert(allAlerts.end(), a.begin(), a.end());
    }
    assert(allAlerts.empty());

    // 10th packet: should trigger PORT_SCAN
    PacketData pkt10;
    pkt10.src_ip = scannerIP;
    pkt10.dst_ip = "192.168.1.55";
    pkt10.dst_port = 1010;
    pkt10.protocol = 6;
    pkt10.length = 64;
    auto a10 = detector.inspectPacket(pkt10);
    assert(!a10.empty());
    assert(a10[0].threat_type == "port_scan");
    assert(a10[0].source_ip == scannerIP);
    std::cout << "  ✓ test_port_scan PASSED\n";
}

void test_mitm_detection() {
    std::cout << "[TEST] Running test_mitm_detection...\n";
    ThreatDetector detector;
    detector.setMitmThreshold(50);

    std::string targetIP = "192.168.1.55";
    std::vector<ThreatAlert> alerts;

    for (int i = 0; i <= 50; ++i) {
        PacketData pkt;
        pkt.src_ip = "192.168.1.188";
        pkt.dst_ip = targetIP;
        pkt.protocol = 6;
        pkt.length = 100;
        auto a = detector.inspectPacket(pkt);
        if (!a.empty()) alerts.insert(alerts.end(), a.begin(), a.end());
    }

    assert(!alerts.empty());
    bool foundMitm = false;
    for (const auto& a : alerts) {
        if (a.threat_type == "mitm_attack") foundMitm = true;
    }
    assert(foundMitm);
    std::cout << "  ✓ test_mitm_detection PASSED\n";
}

void test_bandwidth_anomaly() {
    std::cout << "[TEST] Running test_bandwidth_anomaly...\n";
    ThreatDetector detector;
    detector.setBandwidthLimit(5000); // 5KB limit for testing

    PacketData pkt;
    pkt.src_ip = "192.168.1.77";
    pkt.dst_ip = "192.168.1.1";
    pkt.length = 6000;
    auto alerts = detector.inspectPacket(pkt);
    assert(!alerts.empty());
    assert(alerts[0].threat_type == "data_exfiltration");
    std::cout << "  ✓ test_bandwidth_anomaly PASSED\n";
}

int main() {
    std::cout << "========================================\n";
    std::cout << "  Running C++ ThreatDetector Unit Tests\n";
    std::cout << "========================================\n";
    test_blacklist();
    test_port_scan();
    test_mitm_detection();
    test_bandwidth_anomaly();
    std::cout << "========================================\n";
    std::cout << "  All ThreatDetector Tests PASSED (4/4) \n";
    std::cout << "========================================\n";
    return 0;
}
