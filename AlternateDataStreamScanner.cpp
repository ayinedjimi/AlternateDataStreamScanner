/*******************************************************************************
 * AlternateDataStreamScanner - Scanner de flux de données alternatifs NTFS
 *
 * Auteur  : Ayi NEDJIMI
 * Licence : MIT
 * Description : Énumération et analyse des ADS (Alternate Data Streams) cachés
 *               dans les systèmes NTFS, détection de malware et extraction.
 ******************************************************************************/

#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>
#include <shlwapi.h>
#include <shlobj.h>
#include <string>
#include <vector>
#include <sstream>
#include <fstream>
#include <iomanip>
#include <algorithm>
#include <memory>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "shell32.lib")

#pragma comment(linker, "\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' "\
                        "version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

// Contrôles
#define IDC_EDIT_PATH        1001
#define IDC_BTN_BROWSE       1002
#define IDC_BTN_SCAN         1003
#define IDC_LISTVIEW         1004
#define IDC_BTN_EXTRACT      1005
#define IDC_BTN_DELETE       1006
#define IDC_BTN_EXPORT       1007
#define IDC_EDIT_LOG         1008
#define IDC_PROGRESS         1009
#define IDC_LABEL_STATUS     1010

// Structures
struct ADSInfo {
    std::wstring filePath;
    std::wstring streamName;
    LONGLONG size;
    std::wstring hash;
    bool suspicious;
    std::wstring notes;
};

// RAII
class HandleGuard {
    HANDLE h;
public:
    explicit HandleGuard(HANDLE handle) : h(handle) {}
    ~HandleGuard() { if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h); }
    HANDLE get() const { return h; }
    operator bool() const { return h && h != INVALID_HANDLE_VALUE; }
};

// Globals
HWND g_hMainWnd = nullptr;
HWND g_hListView = nullptr;
HWND g_hLog = nullptr;
HWND g_hProgress = nullptr;
HWND g_hStatus = nullptr;
HWND g_hEditPath = nullptr;
std::vector<ADSInfo> g_streams;
bool g_scanning = false;
int g_foundCount = 0;
int g_suspiciousCount = 0;

void Log(const std::wstring& msg) {
    if (!g_hLog) return;
    int len = GetWindowTextLengthW(g_hLog);
    SendMessageW(g_hLog, EM_SETSEL, len, len);
    SendMessageW(g_hLog, EM_REPLACESEL, FALSE, (LPARAM)(msg + L"\r\n").c_str());
}

std::wstring FormatSize(LONGLONG size) {
    if (size < 1024) return std::to_wstring(size) + L" B";
    if (size < 1024 * 1024) return std::to_wstring(size / 1024) + L" KB";
    if (size < 1024 * 1024 * 1024) return std::to_wstring(size / (1024 * 1024)) + L" MB";
    return std::to_wstring(size / (1024 * 1024 * 1024)) + L" GB";
}

std::wstring CalculateSHA256(const std::wstring& filePath) {
    // Simplified: Return "N/A" - real implementation would use CryptoAPI
    return L"N/A (non implémenté)";
}

bool IsSuspicious(const std::wstring& streamName, LONGLONG size) {
    // Suspicious if:
    // 1. Not the main ::$DATA stream
    // 2. Size > 10 KB
    // 3. Executable extensions in stream name

    if (streamName == L"::$DATA") return false;

    if (size > 10240) return true;

    std::wstring lowerName = streamName;
    std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::towlower);

    if (lowerName.find(L".exe") != std::wstring::npos ||
        lowerName.find(L".dll") != std::wstring::npos ||
        lowerName.find(L".scr") != std::wstring::npos ||
        lowerName.find(L".bat") != std::wstring::npos ||
        lowerName.find(L".cmd") != std::wstring::npos ||
        lowerName.find(L".ps1") != std::wstring::npos) {
        return true;
    }

    return false;
}

bool CheckMZHeader(const std::wstring& fullPath) {
    HANDLE hFile = CreateFileW(fullPath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

    if (hFile == INVALID_HANDLE_VALUE) return false;

    HandleGuard guard(hFile);
    BYTE buffer[2] = {};
    DWORD read = 0;

    if (!ReadFile(hFile, buffer, 2, &read, nullptr)) return false;

    return (read == 2 && buffer[0] == 'M' && buffer[1] == 'Z');
}

void ScanFile(const std::wstring& filePath) {
    WIN32_FIND_STREAM_DATA streamData = {};
    HANDLE hFind = FindFirstStreamW(filePath.c_str(), FindStreamInfoStandard, &streamData, 0);

    if (hFind == INVALID_HANDLE_VALUE) return;

    HandleGuard guard(hFind);

    do {
        std::wstring streamName = streamData.cStreamName;

        // Skip default data stream if it's the only one
        if (streamName == L"::$DATA") {
            continue;
        }

        ADSInfo ads;
        ads.filePath = filePath;
        ads.streamName = streamName;
        ads.size = streamData.StreamSize.QuadPart;
        ads.suspicious = IsSuspicious(streamName, ads.size);

        // Build full stream path
        std::wstring fullStreamPath = filePath + streamName;

        // Check for MZ header
        if (CheckMZHeader(fullStreamPath)) {
            ads.suspicious = true;
            ads.notes = L"Contient un header MZ (exécutable)";
        } else if (ads.suspicious) {
            ads.notes = L"Taille > 10KB ou extension suspecte";
        }

        ads.hash = CalculateSHA256(fullStreamPath);

        g_streams.push_back(ads);
        g_foundCount++;

        if (ads.suspicious) {
            g_suspiciousCount++;
            Log(L"[SUSPECT] " + filePath + streamName);
        }

    } while (FindNextStreamW(hFind, &streamData));
}

void ScanDirectory(const std::wstring& dirPath) {
    if (!g_scanning) return;

    std::wstring searchPath = dirPath + L"\\*";
    WIN32_FIND_DATAW findData = {};

    HANDLE hFind = FindFirstFileW(searchPath.c_str(), &findData);
    if (hFind == INVALID_HANDLE_VALUE) return;

    HandleGuard guard(hFind);

    do {
        if (!g_scanning) break;

        if (wcscmp(findData.cFileName, L".") == 0 || wcscmp(findData.cFileName, L"..") == 0)
            continue;

        std::wstring fullPath = dirPath + L"\\" + findData.cFileName;

        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            // Recursively scan subdirectories
            ScanDirectory(fullPath);
        } else {
            // Scan file for ADS
            ScanFile(fullPath);

            if (g_foundCount % 10 == 0) {
                SendMessageW(g_hProgress, PBM_SETPOS, (g_foundCount / 10) % 100, 0);
            }
        }

    } while (FindNextFileW(hFind, &findData));
}

void UpdateListView() {
    if (!g_hListView) return;

    SendMessageW(g_hListView, WM_SETREDRAW, FALSE, 0);
    ListView_DeleteAllItems(g_hListView);

    int idx = 0;
    for (const auto& ads : g_streams) {
        LVITEMW lvi = {};
        lvi.mask = LVIF_TEXT;
        lvi.iItem = idx++;

        // File path
        lvi.pszText = const_cast<LPWSTR>(ads.filePath.c_str());
        ListView_InsertItem(g_hListView, &lvi);

        // Stream name
        ListView_SetItemText(g_hListView, lvi.iItem, 1, const_cast<LPWSTR>(ads.streamName.c_str()));

        // Size
        std::wstring sizeStr = FormatSize(ads.size);
        ListView_SetItemText(g_hListView, lvi.iItem, 2, const_cast<LPWSTR>(sizeStr.c_str()));

        // Hash
        ListView_SetItemText(g_hListView, lvi.iItem, 3, const_cast<LPWSTR>(ads.hash.c_str()));

        // Suspicious
        std::wstring suspStr = ads.suspicious ? L"OUI" : L"Non";
        ListView_SetItemText(g_hListView, lvi.iItem, 4, const_cast<LPWSTR>(suspStr.c_str()));

        // Notes
        ListView_SetItemText(g_hListView, lvi.iItem, 5, const_cast<LPWSTR>(ads.notes.c_str()));
    }

    SendMessageW(g_hListView, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(g_hListView, nullptr, TRUE);

    std::wstring status = L"ADS trouvés : " + std::to_wstring(g_foundCount) +
                         L" | Suspects : " + std::to_wstring(g_suspiciousCount);
    SetWindowTextW(g_hStatus, status.c_str());
}

DWORD WINAPI ScanThread(LPVOID param) {
    std::wstring path = *reinterpret_cast<std::wstring*>(param);
    delete reinterpret_cast<std::wstring*>(param);

    g_streams.clear();
    g_foundCount = 0;
    g_suspiciousCount = 0;

    Log(L"[INFO] Démarrage du scan : " + path);

    DWORD attrs = GetFileAttributesW(path.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        Log(L"[ERREUR] Chemin invalide");
        g_scanning = false;
        EnableWindow(GetDlgItem(g_hMainWnd, IDC_BTN_SCAN), TRUE);
        return 1;
    }

    if (attrs & FILE_ATTRIBUTE_DIRECTORY) {
        ScanDirectory(path);
    } else {
        ScanFile(path);
    }

    UpdateListView();

    Log(L"[SUCCÈS] Scan terminé : " + std::to_wstring(g_foundCount) +
        L" ADS trouvés, " + std::to_wstring(g_suspiciousCount) + L" suspects");

    g_scanning = false;
    EnableWindow(GetDlgItem(g_hMainWnd, IDC_BTN_SCAN), TRUE);
    SendMessageW(g_hProgress, PBM_SETPOS, 0, 0);

    return 0;
}

void OnBrowse() {
    BROWSEINFOW bi = {};
    bi.hwndOwner = g_hMainWnd;
    bi.lpszTitle = L"Sélectionnez un dossier à scanner";
    bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;

    LPITEMIDLIST pidl = SHBrowseForFolderW(&bi);
    if (pidl) {
        wchar_t path[MAX_PATH] = {};
        if (SHGetPathFromIDListW(pidl, path)) {
            SetWindowTextW(g_hEditPath, path);
        }
        CoTaskMemFree(pidl);
    }
}

void OnScan() {
    if (g_scanning) {
        g_scanning = false;
        EnableWindow(GetDlgItem(g_hMainWnd, IDC_BTN_SCAN), TRUE);
        Log(L"[INFO] Scan annulé par l'utilisateur");
        return;
    }

    wchar_t path[MAX_PATH] = {};
    GetWindowTextW(g_hEditPath, path, MAX_PATH);

    if (wcslen(path) == 0) {
        MessageBoxW(g_hMainWnd, L"Veuillez sélectionner un dossier.", L"Erreur", MB_OK | MB_ICONERROR);
        return;
    }

    g_scanning = true;
    SetWindowTextW(GetDlgItem(g_hMainWnd, IDC_BTN_SCAN), L"Arrêter");

    auto* pathPtr = new std::wstring(path);
    CreateThread(nullptr, 0, ScanThread, pathPtr, 0, nullptr);
}

void OnExtract() {
    int sel = ListView_GetNextItem(g_hListView, -1, LVNI_SELECTED);
    if (sel == -1) {
        MessageBoxW(g_hMainWnd, L"Veuillez sélectionner un ADS.", L"Info", MB_OK | MB_ICONINFORMATION);
        return;
    }

    if (sel >= (int)g_streams.size()) return;

    const auto& ads = g_streams[sel];
    std::wstring fullStreamPath = ads.filePath + ads.streamName;

    OPENFILENAMEW ofn = {};
    wchar_t fileName[MAX_PATH] = L"extracted_ads.bin";

    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g_hMainWnd;
    ofn.lpstrFilter = L"All Files (*.*)\0*.*\0";
    ofn.lpstrFile = fileName;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_OVERWRITEPROMPT;

    if (!GetSaveFileNameW(&ofn)) return;

    if (!CopyFileW(fullStreamPath.c_str(), fileName, FALSE)) {
        MessageBoxW(g_hMainWnd, L"Échec de l'extraction.", L"Erreur", MB_OK | MB_ICONERROR);
        return;
    }

    Log(L"[SUCCÈS] ADS extrait : " + std::wstring(fileName));
    MessageBoxW(g_hMainWnd, L"ADS extrait avec succès.", L"Succès", MB_OK | MB_ICONINFORMATION);
}

void OnDelete() {
    int sel = ListView_GetNextItem(g_hListView, -1, LVNI_SELECTED);
    if (sel == -1) {
        MessageBoxW(g_hMainWnd, L"Veuillez sélectionner un ADS.", L"Info", MB_OK | MB_ICONINFORMATION);
        return;
    }

    if (sel >= (int)g_streams.size()) return;

    const auto& ads = g_streams[sel];

    int result = MessageBoxW(g_hMainWnd,
                            (L"Voulez-vous vraiment supprimer cet ADS ?\n\n" +
                             ads.filePath + ads.streamName).c_str(),
                            L"Confirmation", MB_YESNO | MB_ICONWARNING);

    if (result != IDYES) return;

    std::wstring fullStreamPath = ads.filePath + ads.streamName;

    if (!DeleteFileW(fullStreamPath.c_str())) {
        MessageBoxW(g_hMainWnd, L"Échec de la suppression.", L"Erreur", MB_OK | MB_ICONERROR);
        return;
    }

    Log(L"[SUCCÈS] ADS supprimé : " + fullStreamPath);
    g_streams.erase(g_streams.begin() + sel);
    UpdateListView();
}

void OnExport() {
    if (g_streams.empty()) {
        MessageBoxW(g_hMainWnd, L"Aucune donnée à exporter.", L"Info", MB_OK | MB_ICONINFORMATION);
        return;
    }

    OPENFILENAMEW ofn = {};
    wchar_t fileName[MAX_PATH] = L"ads_scan_results.csv";

    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g_hMainWnd;
    ofn.lpstrFilter = L"CSV Files (*.csv)\0*.csv\0All Files (*.*)\0*.*\0";
    ofn.lpstrFile = fileName;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrDefExt = L"csv";
    ofn.Flags = OFN_OVERWRITEPROMPT;

    if (!GetSaveFileNameW(&ofn)) return;

    std::wofstream ofs(fileName);
    if (!ofs) {
        MessageBoxW(g_hMainWnd, L"Impossible de créer le fichier.", L"Erreur", MB_OK | MB_ICONERROR);
        return;
    }

    ofs.imbue(std::locale(""));

    ofs << L"CheminFichier,NomStream,Taille,Hash,Suspect,Notes\n";

    for (const auto& ads : g_streams) {
        ofs << L"\"" << ads.filePath << L"\","
            << L"\"" << ads.streamName << L"\","
            << ads.size << L","
            << L"\"" << ads.hash << L"\","
            << (ads.suspicious ? L"OUI" : L"Non") << L","
            << L"\"" << ads.notes << L"\"\n";
    }

    ofs.close();
    Log(L"[SUCCÈS] Résultats exportés : " + std::wstring(fileName));
    MessageBoxW(g_hMainWnd, L"Résultats exportés avec succès.", L"Succès", MB_OK | MB_ICONINFORMATION);
}

void InitListView(HWND hList) {
    ListView_SetExtendedListViewStyle(hList, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);

    LVCOLUMNW lvc = {};
    lvc.mask = LVCF_TEXT | LVCF_WIDTH;

    lvc.pszText = const_cast<LPWSTR>(L"Chemin Fichier");
    lvc.cx = 250;
    ListView_InsertColumn(hList, 0, &lvc);

    lvc.pszText = const_cast<LPWSTR>(L"Nom Stream");
    lvc.cx = 150;
    ListView_InsertColumn(hList, 1, &lvc);

    lvc.pszText = const_cast<LPWSTR>(L"Taille");
    lvc.cx = 100;
    ListView_InsertColumn(hList, 2, &lvc);

    lvc.pszText = const_cast<LPWSTR>(L"Hash");
    lvc.cx = 150;
    ListView_InsertColumn(hList, 3, &lvc);

    lvc.pszText = const_cast<LPWSTR>(L"Suspect");
    lvc.cx = 70;
    ListView_InsertColumn(hList, 4, &lvc);

    lvc.pszText = const_cast<LPWSTR>(L"Notes");
    lvc.cx = 200;
    ListView_InsertColumn(hList, 5, &lvc);
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE: {
            // Path controls
            CreateWindowW(L"STATIC", L"Dossier à scanner :", WS_CHILD | WS_VISIBLE,
                         10, 15, 120, 20, hwnd, nullptr, nullptr, nullptr);

            g_hEditPath = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"C:\\",
                                          WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
                                          140, 12, 400, 22, hwnd, (HMENU)IDC_EDIT_PATH, nullptr, nullptr);

            CreateWindowW(L"BUTTON", L"Parcourir...", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                         550, 10, 100, 25, hwnd, (HMENU)IDC_BTN_BROWSE, nullptr, nullptr);

            CreateWindowW(L"BUTTON", L"Scanner", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                         660, 10, 100, 25, hwnd, (HMENU)IDC_BTN_SCAN, nullptr, nullptr);

            // Progress
            g_hProgress = CreateWindowW(PROGRESS_CLASSW, nullptr, WS_CHILD | WS_VISIBLE | PBS_SMOOTH,
                                        10, 45, 750, 20, hwnd, (HMENU)IDC_PROGRESS, nullptr, nullptr);
            SendMessageW(g_hProgress, PBM_SETRANGE, 0, MAKELPARAM(0, 100));

            // ListView
            g_hListView = CreateWindowExW(0, WC_LISTVIEWW, nullptr,
                                          WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | WS_BORDER,
                                          10, 75, 760, 280, hwnd, (HMENU)IDC_LISTVIEW, nullptr, nullptr);
            InitListView(g_hListView);

            // Action buttons
            CreateWindowW(L"BUTTON", L"Extraire Stream", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                         10, 365, 120, 25, hwnd, (HMENU)IDC_BTN_EXTRACT, nullptr, nullptr);

            CreateWindowW(L"BUTTON", L"Supprimer ADS", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                         140, 365, 120, 25, hwnd, (HMENU)IDC_BTN_DELETE, nullptr, nullptr);

            CreateWindowW(L"BUTTON", L"Exporter Résultats", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                         270, 365, 140, 25, hwnd, (HMENU)IDC_BTN_EXPORT, nullptr, nullptr);

            // Status
            g_hStatus = CreateWindowW(L"STATIC", L"Prêt - Sélectionnez un dossier et cliquez sur Scanner",
                                      WS_CHILD | WS_VISIBLE | SS_LEFT,
                                      10, 400, 760, 20, hwnd, (HMENU)IDC_LABEL_STATUS, nullptr, nullptr);

            // Log
            CreateWindowW(L"STATIC", L"Journal :", WS_CHILD | WS_VISIBLE,
                         10, 425, 100, 20, hwnd, nullptr, nullptr, nullptr);

            g_hLog = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", nullptr,
                                     WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
                                     10, 445, 760, 100, hwnd, (HMENU)IDC_EDIT_LOG, nullptr, nullptr);

            Log(L"AlternateDataStreamScanner - Scanner de flux de données alternatifs NTFS");
            Log(L"Auteur : Ayi NEDJIMI");
            Log(L"Prêt à scanner les ADS.");

            return 0;
        }

        case WM_COMMAND: {
            switch (LOWORD(wParam)) {
                case IDC_BTN_BROWSE:
                    OnBrowse();
                    break;
                case IDC_BTN_SCAN:
                    OnScan();
                    break;
                case IDC_BTN_EXTRACT:
                    OnExtract();
                    break;
                case IDC_BTN_DELETE:
                    OnDelete();
                    break;
                case IDC_BTN_EXPORT:
                    OnExport();
                    break;
            }
            return 0;
        }

        case WM_DESTROY:
            g_scanning = false;
            PostQuitMessage(0);
            return 0;
    }

    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, LPWSTR, int nCmdShow) {
    CoInitialize(nullptr);

    INITCOMMONCONTROLSEX icc = {};
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_LISTVIEW_CLASSES | ICC_PROGRESS_CLASS;
    InitCommonControlsEx(&icc);

    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"ADSScannerClass";
    wc.hIcon = LoadIcon(nullptr, IDI_APPLICATION);

    RegisterClassExW(&wc);

    g_hMainWnd = CreateWindowExW(0, wc.lpszClassName,
                                 L"AlternateDataStreamScanner - Scanner ADS NTFS | Ayi NEDJIMI",
                                 WS_OVERLAPPEDWINDOW,
                                 CW_USEDEFAULT, CW_USEDEFAULT, 800, 620,
                                 nullptr, nullptr, hInstance, nullptr);

    ShowWindow(g_hMainWnd, nCmdShow);
    UpdateWindow(g_hMainWnd);

    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    CoUninitialize();
    return (int)msg.wParam;
}
