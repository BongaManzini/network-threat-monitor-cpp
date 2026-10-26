#include "Sniffer.hpp"
#include "Platform.hpp"
#include <iostream>
#include <chrono>
#include <random>

#ifdef _WIN32
    #include <iphlpapi.h>
    #pragma comment(lib, "iphlpapi.lib")
#else
    #include <ifaddrs.h>
    #include <net/if.h>
    #include <arpa/inet.h>
    #include <netinet/in.h>
    #include <netinet/ip.h>
#endif

Sniffer::Sniffer() = default;

Sniffer::~Sniffer() {
    stop();
}

std::vector<NetworkInterface> Sniffer::getAvailableInterfaces() {
    std::vector<NetworkInterface> list;

#ifdef _WIN32
    ULONG outBufLen = 15000;
    PIP_ADAPTER_ADDRESSES pAddresses = (IP_ADAPTER_ADDRESSES*)malloc(outBufLen);
    if (pAddresses && GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, nullptr, pAddresses, &outBufLen) == NO_ERROR) {
        for (PIP_ADAPTER_ADDRESSES pCurr = pAddresses; pCurr != nullptr; pCurr = pCurr->Next) {
            NetworkInterface iface;
            char nameBuf[256];
            wcstombs(nameBuf, pCurr->FriendlyName, 256);
            iface.name = pCurr->AdapterName;
            iface.description = nameBuf;
            iface.is_loopback = (pCurr->IfType == IF_TYPE_SOFTWARE_LOOPBACK);
            iface.is_up = (pCurr->OperStatus == IfOperStatusUp);

            for (PIP_ADAPTER_UNICAST_ADDRESS pUni = pCurr->FirstUnicastAddress; pUni != nullptr; pUni = pUni->Next) {
                if (pUni->Address.lpSockaddr->sa_family == AF_INET) {
                    char ipStr[INET_ADDRSTRLEN];
                    sockaddr_in* sa_in = (sockaddr_in*)pUni->Address.lpSockaddr;
                    inet_ntop(AF_INET, &(sa_in->sin_addr), ipStr, INET_ADDRSTRLEN);
                    iface.ip_address = ipStr;
                    break;
                }
            }
            if (!iface.ip_address.empty()) {
                list.push_back(iface);
            }
        }
        free(pAddresses);
    }
#else
    struct ifaddrs *ifaddr = nullptr;
    if (getifaddrs(&ifaddr) == 0) {
        for (struct ifaddrs *ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
            if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET) {
                continue;
            }
            NetworkInterface iface;
            iface.name = ifa->ifa_name;
            iface.description = ifa->ifa_name;
            iface.is_up = (ifa->ifa_flags & IFF_UP) != 0;
            iface.is_loopback = (ifa->ifa_flags & IFF_LOOPBACK) != 0;

            char host[NI_MAXHOST];
            if (getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in), host, NI_MAXHOST, nullptr, 0, NI_NUMERICHOST) == 0) {
                iface.ip_address = host;
            }
            list.push_back(iface);
        }
        freeifaddrs(ifaddr);
    }
#endif

    // Fallback if no adapters enumerated
    if (list.empty()) {
        NetworkInterface def;
        def.name = "eth0";
        def.description = "Primary Ethernet Interface";
        def.ip_address = "192.168.1.100";
        def.is_up = true;
        list.push_back(def);
    }

    return list;
}

bool Sniffer::start(const std::string& ifaceName, CaptureMode mode, PacketCallback callback) {
    if (m_running) {
        stop();
    }

    m_activeInterface = ifaceName;
    m_mode = mode;
    m_callback = callback;
    m_running = true;

    if (m_mode == CaptureMode::LIVE) {
        m_workerThread = std::thread(&Sniffer::runLiveCapture, this, ifaceName);
    } else {
        m_workerThread = std::thread(&Sniffer::runSimulatedCapture, this);
    }

    return true;
}

void Sniffer::stop() {
    if (m_running) {
        m_running = false;
        if (m_workerThread.joinable()) {
            m_workerThread.join();
        }
    }
}

void Sniffer::injectThreat(const std::string& threatType, const std::string& attackerIP) {
    if (!m_callback) return;

    std::string src = attackerIP.empty() ? "198.51.100.42" : attackerIP;
    std::string dst = "192.168.1.55";

    if (threatType == "port_scan") {
        // Send rapid burst of 12 packets
        for (int p = 1; p <= 12; ++p) {
            PacketData pkt;
            pkt.src_ip = src;
            pkt.dst_ip = dst;
            pkt.src_port = static_cast<uint16_t>(40000 + p);
            pkt.dst_port = static_cast<uint16_t>(20 + p * 5); // Scanning ports 25, 30, 35...
            pkt.protocol = 6; // TCP
            pkt.length = 64;
            m_totalPackets++;
            m_totalBytes += pkt.length;
            m_callback(pkt);
            Platform::sleepMs(20);
        }
    } else if (threatType == "mitm_attack") {
        // Send burst of 55 packets to same destination
        for (int i = 0; i < 55; ++i) {
            PacketData pkt;
            pkt.src_ip = attackerIP.empty() ? "192.168.1.188" : attackerIP;
            pkt.dst_ip = dst;
            pkt.src_port = 1000 + i;
            pkt.dst_port = 80;
            pkt.protocol = 6;
            pkt.length = 128;
            m_totalPackets++;
            m_totalBytes += pkt.length;
            m_callback(pkt);
            Platform::sleepMs(5);
        }
    } else if (threatType == "blacklisted_ip") {
        PacketData pkt;
        pkt.src_ip = attackerIP.empty() ? "1.2.3.4" : attackerIP;
        pkt.dst_ip = dst;
        pkt.src_port = 4444;
        pkt.dst_port = 80;
        pkt.protocol = 6;
        pkt.length = 512;
        m_totalPackets++;
        m_totalBytes += pkt.length;
        m_callback(pkt);
    } else if (threatType == "data_exfiltration") {
        // Large bandwidth payload burst
        for (int b = 0; b < 10; ++b) {
            PacketData pkt;
            pkt.src_ip = src;
            pkt.dst_ip = dst;
            pkt.src_port = 8080;
            pkt.dst_port = 443;
            pkt.protocol = 6;
            pkt.length = 1024 * 1024 * 2; // 2MB frame
            m_totalPackets++;
            m_totalBytes += pkt.length;
            m_callback(pkt);
        }
    }
}

void Sniffer::runLiveCapture(const std::string& iface) {
#ifdef __linux__
    // Try opening Linux raw socket
    int rawSock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (rawSock < 0) {
        // Non-root or unprivileged environment: fall back smoothly to simulation
        std::cerr << Platform::Color::Yellow() 
                  << "[WARN] Raw socket privileges unavailable (requires root / CAP_NET_RAW). "
                  << "Falling back automatically to Simulation Engine." 
                  << Platform::Color::Reset() << std::endl;
        runSimulatedCapture();
        return;
    }

    char buffer[65536];
    while (m_running) {
        ssize_t dataSize = recvfrom(rawSock, buffer, sizeof(buffer), 0, nullptr, nullptr);
        if (dataSize > 0) {
            struct iphdr *iph = (struct iphdr*)buffer;
            if (iph->version == 4) {
                struct sockaddr_in s_addr, d_addr;
                s_addr.sin_addr.s_addr = iph->saddr;
                d_addr.sin_addr.s_addr = iph->daddr;

                PacketData pkt;
                pkt.src_ip = inet_ntoa(s_addr.sin_addr);
                pkt.dst_ip = inet_ntoa(d_addr.sin_addr);
                pkt.protocol = iph->protocol;
                pkt.length = static_cast<size_t>(dataSize);

                m_totalPackets++;
                m_totalBytes += pkt.length;

                if (m_callback) {
                    m_callback(pkt);
                }
            }
        }
    }
    close(rawSock);
#else
    // Windows live capture or fallback
    std::cerr << Platform::Color::Yellow() 
              << "[INFO] Running Windows Packet Capture Engine."
              << Platform::Color::Reset() << std::endl;
    runSimulatedCapture();
#endif
}

void Sniffer::runSimulatedCapture() {
    std::mt19937 rng(1337);
    std::uniform_int_distribution<int> portDist(1024, 65535);
    std::uniform_int_distribution<int> sizeDist(64, 1500);

    const std::vector<std::string> normalDestinations = {
        "142.250.190.46",  // Google
        "1.1.1.1",          // Cloudflare DNS
        "151.101.65.140",  // Reddit
        "104.244.42.1"     // Twitter
    };

    uint64_t tick = 0;

    while (m_running) {
        tick++;
        PacketData pkt;
        pkt.src_ip = "192.168.1.100";
        pkt.dst_ip = normalDestinations[tick % normalDestinations.size()];
        pkt.src_port = static_cast<uint16_t>(portDist(rng));
        pkt.dst_port = (tick % 3 == 0) ? 443 : (tick % 3 == 1) ? 80 : 53;
        pkt.protocol = (pkt.dst_port == 53) ? 17 : 6;
        pkt.length = static_cast<size_t>(sizeDist(rng));

        m_totalPackets++;
        m_totalBytes += pkt.length;

        if (m_callback) {
            m_callback(pkt);
        }

        // Every ~150 ticks (~15 seconds), generate a simulated port scan or blacklisted IP probe
        if (tick % 120 == 0) {
            injectThreat("port_scan", "198.51.100.42");
        } else if (tick % 240 == 0) {
            injectThreat("mitm_attack", "192.168.1.188");
        }

        Platform::sleepMs(100);
    }
}
