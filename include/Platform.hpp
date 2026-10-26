#pragma once

#include <string>
#include <vector>
#include <chrono>
#include <thread>
#include <iostream>
#include <sstream>

#ifdef _WIN32
    #ifndef WIN32_LEAN_AND_MEAN
        #define WIN32_LEAN_AND_MEAN
    #endif
    #include <windows.h>
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <shlobj.h>
    #pragma comment(lib, "ws2_32.lib")
    typedef SOCKET socket_t;
    #define CLOSESOCKET(s) closesocket(s)
    #define IS_INVALID_SOCKET(s) ((s) == INVALID_SOCKET)
#else
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <netinet/ip.h>
    #include <netinet/tcp.h>
    #include <netinet/udp.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <netdb.h>
    #include <fcntl.h>
    #include <errno.h>
    #include <sys/stat.h>
    #include <ifaddrs.h>
    #include <net/if.h>
    typedef int socket_t;
    #define INVALID_SOCKET (-1)
    #define SOCKET_ERROR   (-1)
    #define CLOSESOCKET(s) ::close(s)
    #define IS_INVALID_SOCKET(s) ((s) < 0)
#endif

namespace Platform {

    inline bool initSockets() {
#ifdef _WIN32
        WSADATA wsaData;
        return (WSAStartup(MAKEWORD(2, 2), &wsaData) == 0);
#else
        return true;
#endif
    }

    inline void cleanupSockets() {
#ifdef _WIN32
        WSACleanup();
#endif
    }

    inline void sleepMs(int milliseconds) {
        std::this_thread::sleep_for(std::chrono::milliseconds(milliseconds));
    }

    inline std::string getOSName() {
#ifdef _WIN32
        return "Windows";
#elif defined(__linux__)
        return "Linux";
#elif defined(__APPLE__)
        return "macOS";
#else
        return "Unix-like";
#endif
    }

    inline std::string getLogFilePath() {
#ifdef _WIN32
        wchar_t path[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_APPDATA, nullptr, 0, path))) {
            char narrow[MAX_PATH];
            wcstombs(narrow, path, MAX_PATH);
            std::string dir = std::string(narrow) + "\\NetThreatDetection";
            CreateDirectoryA(dir.c_str(), nullptr);
            return dir + "\\packet_log.txt";
        }
        return "packet_log.txt";
#else
        const char* home = getenv("HOME");
        std::string base = home ? home : ".";
        std::string dir = base + "/.local/share/NetThreatDetection";
        mkdir((base + "/.local").c_str(), 0755);
        mkdir((base + "/.local/share").c_str(), 0755);
        mkdir(dir.c_str(), 0755);
        return dir + "/packet_log.txt";
#endif
    }

    inline void enableVTMode() {
#ifdef _WIN32
        HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
        if (hOut != INVALID_HANDLE_VALUE) {
            DWORD dwMode = 0;
            if (GetConsoleMode(hOut, &dwMode)) {
                dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
                SetConsoleMode(hOut, dwMode);
            }
        }
#endif
    }

    namespace Color {
        inline const char* Reset()   { return "\033[0m"; }
        inline const char* Bold()    { return "\033[1m"; }
        inline const char* Red()     { return "\033[31m"; }
        inline const char* Green()   { return "\033[32m"; }
        inline const char* Yellow()  { return "\033[33m"; }
        inline const char* Blue()    { return "\033[34m"; }
        inline const char* Magenta() { return "\033[35m"; }
        inline const char* Cyan()    { return "\033[36m"; }
        inline const char* White()   { return "\033[37m"; }
        inline const char* Dim()     { return "\033[2m"; }
    }
}
