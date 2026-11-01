// injector.cpp — GUI subsystem, auto-elevate, optional silent mode via -s
#include <windows.h>
#include <tlhelp32.h>
#include <shellapi.h>
#include <string>

#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "user32.lib")

static bool g_silent = false;

static void ShowError(const std::wstring& msg) {
    if (!g_silent)
        MessageBoxW(nullptr, msg.c_str(), L"Injector Error",
                    MB_ICONERROR | MB_OK);
}

static void ShowInfo(const std::wstring& msg) {
    if (!g_silent)
        MessageBoxW(nullptr, msg.c_str(), L"Injector",
                    MB_ICONINFORMATION | MB_OK);
}

static bool IsElevated() {
    BOOL b = FALSE;
    HANDLE hToken = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION te{};
        DWORD sz = sizeof(te);
        if (GetTokenInformation(hToken, TokenElevation, &te, sz, &sz))
            b = te.TokenIsElevated;
        CloseHandle(hToken);
    }
    return b != FALSE;
}

// 从完整命令行中提取参数部分（去掉 exe 路径），用于提权重启时透传
static std::wstring GetParamsPart() {
    LPWSTR cmd = GetCommandLineW();
    LPWSTR p = cmd;
    if (*p == L'"') {
        p++;
        while (*p && *p != L'"') p++;
        if (*p == L'"') p++;
    } else {
        while (*p && *p != L' ' && *p != L'\t') p++;
    }
    while (*p == L' ' || *p == L'\t') p++;
    return std::wstring(p);
}

static DWORD FindPid(const std::wstring& exeName) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    DWORD pid = 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, exeName.c_str()) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

static std::wstring GetExeDir() {
    wchar_t buf[MAX_PATH];
    DWORD n = GetModuleFileNameW(nullptr, buf, MAX_PATH);
    std::wstring s(buf, n);
    size_t pos = s.find_last_of(L"\\/");
    if (pos != std::wstring::npos) s.resize(pos + 1);
    return s;
}

static bool InjectDll(DWORD pid, const std::wstring& dllPath, std::wstring& err) {
    HANDLE hProc = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION  | PROCESS_VM_WRITE,
        FALSE, pid);
    if (!hProc) {
        DWORD e = GetLastError();
        wchar_t buf[256];
        wsprintfW(buf,
            L"OpenProcess failed (error %lu).\n"
            L"Run as administrator if the target process is elevated.", e);
        err = buf;
        return false;
    }

    BOOL targetWow64 = FALSE;
    IsWow64Process(hProc, &targetWow64);
#ifdef _WIN64
    if (targetWow64) {
        err = L"Target is 32-bit but this injector is 64-bit.\n"
              L"Use a 32-bit injector and 32-bit DLL.";
        CloseHandle(hProc);
        return false;
    }
#else
    SYSTEM_INFO si{};
    GetNativeSystemInfo(&si);
    if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 && !targetWow64) {
        err = L"Target is 64-bit but this injector is 32-bit.\n"
              L"Use a 64-bit injector and 64-bit DLL.";
        CloseHandle(hProc);
        return false;
    }
#endif

    SIZE_T bytes = (dllPath.size() + 1) * sizeof(wchar_t);
    void* remote = VirtualAllocEx(hProc, nullptr, bytes,
                                  MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote) {
        DWORD e = GetLastError();
        wchar_t buf[256];
        wsprintfW(buf, L"VirtualAllocEx failed (error %lu).", e);
        err = buf;
        CloseHandle(hProc);
        return false;
    }

    SIZE_T written = 0;
    if (!WriteProcessMemory(hProc, remote, dllPath.c_str(), bytes, &written)) {
        DWORD e = GetLastError();
        wchar_t buf[256];
        wsprintfW(buf, L"WriteProcessMemory failed (error %lu).", e);
        err = buf;
        VirtualFreeEx(hProc, remote, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }

    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    auto pLoadLib = (LPTHREAD_START_ROUTINE)GetProcAddress(k32, "LoadLibraryW");
    if (!pLoadLib) {
        DWORD e = GetLastError();
        wchar_t buf[256];
        wsprintfW(buf, L"GetProcAddress(LoadLibraryW) failed (error %lu).", e);
        err = buf;
        VirtualFreeEx(hProc, remote, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }

    HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0, pLoadLib, remote, 0, nullptr);
    if (!hThread) {
        DWORD e = GetLastError();
        wchar_t buf[256];
        wsprintfW(buf,
            L"CreateRemoteThread failed (error %lu).\n"
            L"Run as administrator if the target process is elevated.", e);
        err = buf;
        VirtualFreeEx(hProc, remote, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }

    DWORD wait = WaitForSingleObject(hThread, 10000);
    bool ok = false;
    if (wait == WAIT_OBJECT_0) {
        DWORD code = 0;
        GetExitCodeThread(hThread, &code);
        ok = (code != 0);
        if (!ok) {
            err = L"LoadLibraryW returned 0 inside the target process.\n"
                  L"Check DLL architecture, path, and runtime dependencies.";
        }
    } else if (wait == WAIT_TIMEOUT) {
        err = L"Remote thread timed out after 10 seconds.";
    } else {
        DWORD e = GetLastError();
        wchar_t buf[256];
        wsprintfW(buf, L"WaitForSingleObject failed (error %lu).", e);
        err = buf;
    }

    CloseHandle(hThread);
    VirtualFreeEx(hProc, remote, 0, MEM_RELEASE);
    CloseHandle(hProc);
    return ok;
}

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    // ---------- 1. 参数解析 ----------
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    std::wstring exeName, dllName;
    if (argv) {
        for (int i = 1; i < argc; ++i) {
            if (_wcsicmp(argv[i], L"-s") == 0)
                g_silent = true;
            else if (exeName.empty())
                exeName = argv[i];
            else if (dllName.empty())
                dllName = argv[i];
        }
        LocalFree(argv);
    }
    if (exeName.empty()) exeName = L"StudentMain.exe";
    if (dllName.empty()) dllName = L"hook_x86.dll";

    // ---------- 2. 自动提权 ----------
    if (!IsElevated()) {
        wchar_t exePath[MAX_PATH];
        GetModuleFileNameW(nullptr, exePath, MAX_PATH);
        std::wstring params = GetParamsPart();

        SHELLEXECUTEINFOW sei{};
        sei.cbSize = sizeof(sei);
        sei.fMask = SEE_MASK_NOCLOSEPROCESS;
        sei.lpVerb = L"runas";
        sei.lpFile = exePath;
        sei.lpParameters = params.empty() ? nullptr : params.c_str();
        sei.nShow = SW_HIDE;

        if (!ShellExecuteExW(&sei) || !sei.hProcess) {
            DWORD e = GetLastError();
            if (e == ERROR_CANCELLED) {
                ShowError(L"Elevation was cancelled by the user.\n"
                          L"Administrator privileges are required.");
            } else {
                wchar_t buf[256];
                wsprintfW(buf,
                    L"Failed to elevate (error %lu).\n"
                    L"Administrator privileges are required.", e);
                ShowError(buf);
            }
            return 1;
        }

        WaitForSingleObject(sei.hProcess, INFINITE);
        DWORD exitCode = 1;
        GetExitCodeProcess(sei.hProcess, &exitCode);
        CloseHandle(sei.hProcess);
        return (int)exitCode;
    }

    // ---------- 3. 业务逻辑 ----------
    std::wstring dllPath = GetExeDir() + dllName;

    if (GetFileAttributesW(dllPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        ShowError(L"DLL not found:\n" + dllPath +
                  L"\n\nPlace the DLL next to this injector.");
        return 1;
    }

    DWORD pid = FindPid(exeName);
    if (!pid) {
        ShowError(L"Process not found: " + exeName);
        return 1;
    }

    std::wstring err;
    if (InjectDll(pid, dllPath, err)) {
        wchar_t buf[256];
        wsprintfW(buf, L"Injection succeeded.\nTarget: %s\nPID: %lu",
                  exeName.c_str(), pid);
        ShowInfo(buf);
        return 0;
    }

    ShowError(L"Injection failed for " + exeName + L" (PID " +
              std::to_wstring(pid) + L").\n\n" + err);
    return 1;
}