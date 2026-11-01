// hook64.cpp
#include <windows.h>
#include <thread>
#include <chrono>
#include "MinHook.h"

static HINSTANCE g_hInst = nullptr;
static DWORD g_dwProcessId = 0;
static volatile bool g_bRunning = true;

static HHOOK g_hCbtHook = nullptr;
static HHOOK g_hCallWndProcHook = nullptr;

typedef BOOL(WINAPI* pSetWindowPos)(HWND, HWND, int, int, int, int, UINT);
static pSetWindowPos g_pOriginalSetWindowPos = nullptr;

static BOOL IsOwnWindow(HWND hwnd) {
    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    return pid == g_dwProcessId;
}

static void ForceNonTopmost(HWND hwnd) {
    if (!IsWindow(hwnd)) return;
    g_pOriginalSetWindowPos(hwnd, HWND_NOTOPMOST, 0, 0, 0, 0,
        SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
}

// 防线 1：WH_CBT —— 阻止激活与焦点抢占
static LRESULT CALLBACK CbtProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode == HCBT_ACTIVATE || nCode == HCBT_SETFOCUS) {
        HWND hwnd = (HWND)wParam;
        if (IsOwnWindow(hwnd)) return 1;
    }
    return CallNextHookEx(g_hCbtHook, nCode, wParam, lParam);
}

// 防线 2：WH_CALLWNDPROC —— 窗口显示瞬间若为置顶则降级
static LRESULT CALLBACK CallWndProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode == HC_ACTION) {
        CWPSTRUCT* pMsg = (CWPSTRUCT*)lParam;
        if (pMsg && pMsg->message == WM_SHOWWINDOW && pMsg->wParam == TRUE) {
            if (IsOwnWindow(pMsg->hwnd)) {
                if (GetWindowLongPtr(pMsg->hwnd, GWL_EXSTYLE) & WS_EX_TOPMOST) {
                    ForceNonTopmost(pMsg->hwnd);
                }
            }
        }
    }
    return CallNextHookEx(g_hCallWndProcHook, nCode, wParam, lParam);
}

// 防线 3：SetWindowPos 挂钩 —— 把 HWND_TOPMOST 改写成 HWND_NOTOPMOST
static BOOL WINAPI DetourSetWindowPos(HWND hWnd, HWND hWndInsertAfter,
    int X, int Y, int cx, int cy, UINT uFlags)
{
    if (IsOwnWindow(hWnd)) {
        if (hWndInsertAfter == HWND_TOPMOST) {
            hWndInsertAfter = HWND_NOTOPMOST;
        }
        else if (hWndInsertAfter == HWND_TOP) {
            uFlags |= SWP_NOZORDER;
        }
    }
    return g_pOriginalSetWindowPos(hWnd, hWndInsertAfter, X, Y, cx, cy, uFlags);
}

// 巡检：只处理可见窗口
static BOOL CALLBACK EnumClearTopmostProc(HWND hwnd, LPARAM) {
    if (!IsOwnWindow(hwnd)) return TRUE;
    if (!IsWindowVisible(hwnd)) return TRUE;
    LONG_PTR exStyle = GetWindowLongPtr(hwnd, GWL_EXSTYLE);
    if (exStyle & WS_EX_TOPMOST) {
        ForceNonTopmost(hwnd);
    }
    return TRUE;
}

static void CheckLoop() {
    while (g_bRunning) {
        EnumWindows(EnumClearTopmostProc, 0);
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
    }
}

static void ShowErrorBox(const wchar_t* step, DWORD code) {
    wchar_t buf[512];
    wsprintfW(buf, L"[hook_x64] %s 失败。\n错误码: %lu (0x%08lX)", step, code, code);
    MessageBoxW(nullptr, buf, L"注入钩子错误", MB_ICONERROR | MB_OK);
}

static bool InstallHooks() {
    MH_STATUS st = MH_Initialize();
    if (st != MH_OK) {
        ShowErrorBox(L"MH_Initialize", (DWORD)st);
        return false;
    }

    st = MH_CreateHookApi(L"user32.dll", "SetWindowPos",
        reinterpret_cast<LPVOID>(&DetourSetWindowPos),
        reinterpret_cast<LPVOID*>(&g_pOriginalSetWindowPos));
    if (st != MH_OK) {
        ShowErrorBox(L"MH_CreateHookApi(SetWindowPos)", (DWORD)st);
        MH_Uninitialize();
        return false;
    }

    st = MH_EnableHook(MH_ALL_HOOKS);
    if (st != MH_OK) {
        ShowErrorBox(L"MH_EnableHook", (DWORD)st);
        MH_Uninitialize();
        return false;
    }

    g_hCbtHook = SetWindowsHookEx(WH_CBT, CbtProc, g_hInst, 0);
    if (!g_hCbtHook) {
        ShowErrorBox(L"SetWindowsHookEx(WH_CBT)", GetLastError());
    }

    g_hCallWndProcHook = SetWindowsHookEx(WH_CALLWNDPROC, CallWndProc, g_hInst, 0);
    if (!g_hCallWndProcHook) {
        ShowErrorBox(L"SetWindowsHookEx(WH_CALLWNDPROC)", GetLastError());
    }

    return true;
}

static DWORD WINAPI WorkerProc(LPVOID) {
    Sleep(200); // 等 DllMain 返回，loader lock 释放

    if (!InstallHooks()) {
        return 0;
    }

    std::thread(CheckLoop).detach();
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinstDLL);
        g_hInst = hinstDLL;
        g_dwProcessId = GetCurrentProcessId();

        HANDLE h = CreateThread(nullptr, 0, WorkerProc, nullptr, 0, nullptr);
        if (h) CloseHandle(h);
    }
    else if (fdwReason == DLL_PROCESS_DETACH) {
        g_bRunning = false;
        // 不 join、不 Uninitialize，避免退出时挂起线程死锁
    }
    return TRUE;
}