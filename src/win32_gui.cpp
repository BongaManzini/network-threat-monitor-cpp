#ifdef _WIN32
#include "Platform.hpp"
#include "ThreatDetector.hpp"
#include "AegisConnector.hpp"

#include <windows.h>
#include <commctrl.h>
#include <richedit.h>
#include <windowsx.h>
#include <thread>
#include <string>
#include <sstream>
#include <vector>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "Comctl32.lib")

static HWND hLogBox;
static HWND hStartBtn, hStopBtn, hThreatsBtn, hBandwidthChartBtn, hBandwidthGraphBtn, hSyncBtn;
static HWND hInterfaceDropdown;
static HWND hWndMain;
static bool g_capturing = false;
static std::thread g_workerThread;
static std::unique_ptr<AegisConnector> g_aegis;
static std::unique_ptr<ThreatDetector> g_detector;

static std::wstring ToWString(const char* src) {
    if (!src) return L"(null)";
    int len = MultiByteToWideChar(CP_ACP, 0, src, -1, nullptr, 0);
    std::wstring result(len - 1, 0);
    MultiByteToWideChar(CP_ACP, 0, src, -1, &result[0], len);
    return result;
}

static void AppendLog(const std::wstring& message, COLORREF color = RGB(0, 0, 0)) {
    CHARFORMAT cf = { sizeof(cf) };
    cf.dwMask = CFM_COLOR;
    cf.crTextColor = color;
    int len = GetWindowTextLength(hLogBox);
    SendMessage(hLogBox, EM_SETSEL, len, len);
    SendMessage(hLogBox, EM_SETCHARFORMAT, SCF_SELECTION, (LPARAM)&cf);
    SendMessage(hLogBox, EM_REPLACESEL, FALSE, (LPARAM)(message + L"\r\n").c_str());
}

static void ShowThreatDetails() {
    auto threats = g_detector->getThreats();
    std::wstringstream ss;
    ss << L"Threats Detected (" << threats.size() << L"):\n";
    for (const auto& t : threats) {
        ss << ToWString(t.threat_type.c_str()) << L": "
           << ToWString(t.source_ip.c_str()) << L" -> "
           << ToWString(t.target_ip.c_str()) << L" ("
           << ToWString(t.description.c_str()) << L")\n";
    }
    MessageBox(hWndMain, ss.str().c_str(), L"Threat Details", MB_OK | MB_ICONWARNING);
}

static void ShowBandwidthChart() {
    auto bwMap = g_detector->getBandwidthStats();
    std::wstringstream ss;
    ss << L"Bandwidth Usage (KB):\n";
    for (const auto& pair : bwMap) {
        ss << ToWString(pair.first.c_str()) << L": " << pair.second / 1024 << L" KB\n";
    }
    MessageBox(hWndMain, ss.str().c_str(), L"Bandwidth Chart", MB_OK | MB_ICONINFORMATION);
}

static void SyncRulesFromAegis() {
    std::vector<std::string> blocked;
    if (g_aegis && g_aegis->syncBlacklist(blocked)) {
        g_detector->syncBlacklist(blocked);
        std::wstring msg = L"[INFO] Synced " + std::to_wstring(blocked.size()) + L" rules from AEGIS firewall.";
        AppendLog(msg, RGB(0, 128, 0));
        MessageBox(hWndMain, msg.c_str(), L"AEGIS Sync", MB_OK | MB_ICONINFORMATION);
    } else {
        AppendLog(L"[WARN] Could not connect to AEGIS Self-Healing Network.", RGB(255, 0, 0));
    }
}

static void StartCapture() {
    g_capturing = true;
    AppendLog(L"[INFO] Live sniffing initialized with AEGIS Self-Healing link.");
}

static void StopCapture() {
    g_capturing = false;
    AppendLog(L"[INFO] Capture paused.");
}

static LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
    case WM_DESTROY:
        StopCapture();
        PostQuitMessage(0);
        return 0;
    case WM_COMMAND:
        if ((HWND)lParam == hStartBtn) {
            EnableWindow(hStartBtn, FALSE);
            EnableWindow(hStopBtn, TRUE);
            StartCapture();
        } else if ((HWND)lParam == hStopBtn) {
            EnableWindow(hStopBtn, FALSE);
            EnableWindow(hStartBtn, TRUE);
            StopCapture();
        } else if ((HWND)lParam == hThreatsBtn) {
            ShowThreatDetails();
        } else if ((HWND)lParam == hBandwidthChartBtn) {
            ShowBandwidthChart();
        } else if ((HWND)lParam == hSyncBtn) {
            SyncRulesFromAegis();
        }
        return 0;
    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

static void CreateUI(HWND hwnd) {
    hStartBtn = CreateWindow(L"BUTTON", L"Start Capture", WS_VISIBLE | WS_CHILD, 10, 10, 110, 30, hwnd, nullptr, nullptr, nullptr);
    hStopBtn = CreateWindow(L"BUTTON", L"Stop Capture", WS_VISIBLE | WS_CHILD, 130, 10, 110, 30, hwnd, nullptr, nullptr, nullptr);
    hThreatsBtn = CreateWindow(L"BUTTON", L"Show Threats", WS_VISIBLE | WS_CHILD, 250, 10, 110, 30, hwnd, nullptr, nullptr, nullptr);
    hBandwidthChartBtn = CreateWindow(L"BUTTON", L"Show Bandwidth", WS_VISIBLE | WS_CHILD, 370, 10, 120, 30, hwnd, nullptr, nullptr, nullptr);
    hSyncBtn = CreateWindow(L"BUTTON", L"Sync AEGIS Rules", WS_VISIBLE | WS_CHILD, 500, 10, 140, 30, hwnd, nullptr, nullptr, nullptr);
    hInterfaceDropdown = CreateWindow(WC_COMBOBOX, nullptr, CBS_DROPDOWNLIST | WS_VISIBLE | WS_CHILD, 650, 10, 240, 500, hwnd, nullptr, nullptr, nullptr);
    EnableWindow(hStopBtn, FALSE);
    hLogBox = CreateWindowEx(WS_EX_CLIENTEDGE, L"RICHEDIT50W", nullptr,
        WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY,
        10, 50, 930, 550, hwnd, nullptr, nullptr, nullptr);

    SendMessage(hInterfaceDropdown, CB_ADDSTRING, 0, (LPARAM)L"Default Ethernet Adapter");
    ComboBox_SetCurSel(hInterfaceDropdown, 0);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int nCmdShow) {
    Platform::initSockets();
    g_aegis = std::make_unique<AegisConnector>("http://127.0.0.1:5000");
    g_detector = std::make_unique<ThreatDetector>();

    LoadLibrary(L"Msftedit.dll");
    INITCOMMONCONTROLSEX icex = { sizeof(icex), ICC_BAR_CLASSES };
    InitCommonControlsEx(&icex);

    const wchar_t CLASS_NAME[] = L"NetThreatApp";
    WNDCLASS wc = {};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    RegisterClass(&wc);

    hWndMain = CreateWindowEx(0, CLASS_NAME, L"AEGIS C++ Network Threat Monitor (Win32 GUI)",
        WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 980, 680, nullptr, nullptr, hInstance, nullptr);
    if (!hWndMain) return 0;

    CreateUI(hWndMain);
    ShowWindow(hWndMain, nCmdShow);
    AppendLog(L"[INFO] Initialized AEGIS C++ Windows Desktop Sensor.");

    MSG msg = {};
    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    Platform::cleanupSockets();
    return 0;
}
#endif
