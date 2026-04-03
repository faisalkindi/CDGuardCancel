/*
 * CDGuardCancel v1.2 — Guard Cancel During Attacks
 *
 * Supports both controller (XInput) and keyboard/mouse (GetAsyncKeyState).
 * Triple-signal combat detection:
 * - Recent attack button press (RB/RT or Left/Right Click)
 * - Evaluator with activeFlag=1 (animation playing)
 * - Attack button released before guard pressed
 */

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <Xinput.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <safetyhook.hpp>

#pragma comment(lib, "xinput.lib")

static FILE* g_Log = nullptr;
static void Log(const char* fmt, ...) {
    if (!g_Log) return;
    fprintf(g_Log, "[%u] ", GetTickCount());
    va_list ap; va_start(ap, fmt);
    vfprintf(g_Log, fmt, ap);
    va_end(ap);
    fprintf(g_Log, "\n"); fflush(g_Log);
}

static SafetyHookInline g_EvalHook{};
static volatile uint8_t g_GuardHeld = 0;       // guard button (LB or keyboard)
static volatile uint8_t g_AttackHeld = 0;       // attack button currently held
static volatile DWORD g_LastAttackTick = 0;     // last time attack was pressed
static volatile DWORD g_LastActiveTick = 0;     // last time evaluator had activeFlag=1
static volatile uint32_t g_ForceCount = 0;
static volatile uint32_t g_CallCount = 0;
static volatile DWORD g_CombatTimeoutMs = 350;

// Keyboard/mouse virtual key codes (configurable in INI)
static int g_KBGuardKey = VK_CONTROL;           // 0x11 — Ctrl
static int g_KBLightAttackKey = VK_LBUTTON;     // 0x01 — Left Click
static int g_KBHeavyAttackKey = VK_RBUTTON;     // 0x02 — Right Click

static bool g_Enabled = true;
static bool g_LogEnabled = false;

static DWORD WINAPI PollThread(LPVOID) {
    XINPUT_STATE state;
    while (true) {
        Sleep(2);

        bool guardHeld = false;
        bool attackHeld = false;

        // Controller (XInput)
        if (XInputGetState(0, &state) == ERROR_SUCCESS) {
            if (state.Gamepad.wButtons & XINPUT_GAMEPAD_LEFT_SHOULDER)
                guardHeld = true;
            if ((state.Gamepad.wButtons & XINPUT_GAMEPAD_RIGHT_SHOULDER) ||
                state.Gamepad.bRightTrigger > 128)
                attackHeld = true;
        }

        // Keyboard/Mouse (GetAsyncKeyState)
        if (GetAsyncKeyState(g_KBGuardKey) & 0x8000)
            guardHeld = true;
        if ((GetAsyncKeyState(g_KBLightAttackKey) & 0x8000) ||
            (GetAsyncKeyState(g_KBHeavyAttackKey) & 0x8000))
            attackHeld = true;

        // Update shared state
        g_GuardHeld = guardHeld ? 1 : 0;
        g_AttackHeld = attackHeld ? 1 : 0;
        if (attackHeld) {
            g_LastAttackTick = GetTickCount();
        }
    }
}

static uintptr_t AOBScan(uintptr_t start, size_t size, const uint8_t* pat, const char* mask, size_t patLen) {
    for (size_t i = 0; i <= size - patLen; i++) {
        bool found = true;
        __try {
            for (size_t j = 0; j < patLen; j++) {
                if (mask[j] == 'x' && ((const uint8_t*)(start + i))[j] != pat[j]) {
                    found = false;
                    break;
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) { found = false; }
        if (found) return start + i;
    }
    return 0;
}

static uintptr_t ScanExecutable(const uint8_t* pat, const char* mask, size_t patLen) {
    uintptr_t base = (uintptr_t)GetModuleHandleA(NULL);
    auto nt = (IMAGE_NT_HEADERS*)(base + ((IMAGE_DOS_HEADER*)base)->e_lfanew);
    size_t imageSize = nt->OptionalHeader.SizeOfImage;
    MEMORY_BASIC_INFORMATION mbi;
    uintptr_t addr = base, end = base + imageSize;
    while (addr < end) {
        if (!VirtualQuery((void*)addr, &mbi, sizeof(mbi))) break;
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) &&
            !(mbi.Protect & PAGE_GUARD)) {
            uintptr_t rBase = (uintptr_t)mbi.BaseAddress;
            if (rBase < base) rBase = base;
            uintptr_t rEnd = rBase + mbi.RegionSize;
            if (rEnd > end) rEnd = end;
            size_t rSize = rEnd - rBase;
            if (rSize >= patLen) {
                uintptr_t hit = AOBScan(rBase, rSize, pat, mask, patLen);
                if (hit) return hit;
            }
        }
        addr = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
    }
    return 0;
}

static uint64_t __fastcall HookedEval(int64_t param_1, float param_2, uint64_t param_3,
                                       uint32_t param_4, void* param_5, void* param_6) {
    g_CallCount++;

    uint64_t result = g_EvalHook.call<uint64_t>(param_1, param_2, param_3, param_4, param_5, param_6);
    char retVal = (char)(result & 0xFF);
    uint32_t candidateIdx = (uint32_t)(param_3 & 0xFFFFFFFF);

    uint32_t candCount = 0;
    uint8_t activeFlag = 0;
    __try {
        candCount = *(uint32_t*)(param_1 + 0x48);
        activeFlag = *(uint8_t*)(param_1 + 0x6A);
    } __except(EXCEPTION_EXECUTE_HANDLER) {}

    if (activeFlag != 0) {
        g_LastActiveTick = GetTickCount();
    }

    DWORD now = GetTickCount();
    bool recentAttack = (now - g_LastAttackTick) < g_CombatTimeoutMs;
    bool hasActiveEval = (now - g_LastActiveTick) < 500;
    bool attackNotHeld = (g_AttackHeld == 0);
    bool isAttacking = recentAttack && hasActiveEval && attackNotHeld;

    if (retVal == 0 && g_GuardHeld && g_Enabled && isAttacking &&
        candidateIdx == 0 && candCount == 3) {
        g_ForceCount++;
        if (g_LogEnabled && (g_ForceCount % 500 == 1)) {
            Log("FORCING eval=%p active=%u (force#%u)",
                (void*)param_1, activeFlag, g_ForceCount);
        }
        return 1;
    }

    return result;
}

static void TrimValue(char* s) {
    char* sc = strchr(s, ';');
    if (sc) *sc = '\0';
    size_t len = strlen(s);
    while (len > 0 && (s[len-1]==' '||s[len-1]=='\t'||s[len-1]=='\r'||s[len-1]=='\n'))
        s[--len] = '\0';
}

static int ParseVKCode(const char* str) {
    if (str[0] == '0' && (str[1] == 'x' || str[1] == 'X'))
        return (int)strtol(str, NULL, 16);
    return atoi(str);
}

static void LoadINI() {
    char iniPath[MAX_PATH];
    GetModuleFileNameA(NULL, iniPath, MAX_PATH);
    char* sl = strrchr(iniPath, '\\');
    if (sl) strcpy(sl + 1, "CDGuardCancel.ini");
    char buf[64];

    GetPrivateProfileStringA("General", "Enabled", "1", buf, sizeof(buf), iniPath);
    TrimValue(buf); g_Enabled = (atoi(buf) != 0);

    GetPrivateProfileStringA("General", "CombatTimeoutMs", "350", buf, sizeof(buf), iniPath);
    TrimValue(buf); g_CombatTimeoutMs = (DWORD)atoi(buf);
    if (g_CombatTimeoutMs < 100) g_CombatTimeoutMs = 100;
    if (g_CombatTimeoutMs > 10000) g_CombatTimeoutMs = 10000;

    GetPrivateProfileStringA("Keyboard", "GuardKey", "0x11", buf, sizeof(buf), iniPath);
    TrimValue(buf); g_KBGuardKey = ParseVKCode(buf);

    GetPrivateProfileStringA("Keyboard", "LightAttackKey", "0x01", buf, sizeof(buf), iniPath);
    TrimValue(buf); g_KBLightAttackKey = ParseVKCode(buf);

    GetPrivateProfileStringA("Keyboard", "HeavyAttackKey", "0x02", buf, sizeof(buf), iniPath);
    TrimValue(buf); g_KBHeavyAttackKey = ParseVKCode(buf);

    GetPrivateProfileStringA("Debug", "LogEnabled", "0", buf, sizeof(buf), iniPath);
    TrimValue(buf); g_LogEnabled = (atoi(buf) != 0);
}

static DWORD WINAPI MainThread(LPVOID) {
    char logPath[MAX_PATH];
    GetModuleFileNameA(NULL, logPath, MAX_PATH);
    char* sl = strrchr(logPath, '\\');
    if (sl) strcpy(sl + 1, "CDGuardCancel.log");
    g_Log = fopen(logPath, "w");

    Log("CDGuardCancel v1.2 — Guard Cancel (Controller + Keyboard/Mouse)");
    LoadINI();
    Log("Config: Enabled=%d Timeout=%ums Guard=0x%02X LightAtk=0x%02X HeavyAtk=0x%02X Log=%d",
        g_Enabled, g_CombatTimeoutMs, g_KBGuardKey, g_KBLightAttackKey, g_KBHeavyAttackKey, g_LogEnabled);
    Log("Waiting 15s...");
    Sleep(15000);

    CreateThread(NULL, 0, PollThread, NULL, 0, NULL);

    static const uint8_t callSitePat[] = {
        0x0F, 0x28, 0xCE, 0x48, 0x89, 0x4C, 0x24, 0x20, 0x48, 0x8B, 0xCB, 0xE8
    };
    static const char callSiteMask[] = "xxxxxxxxxxxx";

    Log("Scanning...");
    uintptr_t callSite = ScanExecutable(callSitePat, callSiteMask, sizeof(callSitePat));
    if (!callSite) { Log("ERROR: not found"); while(true) Sleep(10000); return 1; }

    uintptr_t callAddr = callSite + 11;
    int32_t relOffset = *(int32_t*)(callAddr + 1);
    uintptr_t evalFunc = callAddr + 5 + relOffset;
    Log("Wrapper at %p", (void*)evalFunc);

    g_EvalHook = safetyhook::create_inline(
        reinterpret_cast<void*>(evalFunc),
        reinterpret_cast<void*>(HookedEval)
    );
    if (!g_EvalHook) { Log("ERROR: hook failed"); while(true) Sleep(10000); return 1; }

    Log("Hook installed!");
    Log("Controller: attack (RB/RT) -> release -> LB = guard cancel");
    Log("Keyboard:   attack (LClick/RClick) -> release -> Ctrl = guard cancel");

    uint32_t lastForce = 0, lastCalls = 0;
    while (true) {
        Sleep(3000);
        LoadINI();
        uint32_t calls = g_CallCount, forces = g_ForceCount;
        if (g_LogEnabled && (calls > lastCalls || forces > lastForce)) {
            Log("calls=%u(+%u) forces=%u(+%u) timeout=%ums guard=%d atk=%d",
                calls, calls-lastCalls, forces, forces-lastForce,
                g_CombatTimeoutMs, g_GuardHeld, g_AttackHeld);
        }
        lastCalls = calls; lastForce = forces;
    }
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        char exePath[MAX_PATH] = {};
        GetModuleFileNameA(NULL, exePath, MAX_PATH);
        const char* exeName = strrchr(exePath, '\\');
        exeName = exeName ? exeName + 1 : exePath;
        if (_stricmp(exeName, "CrimsonDesert.exe") != 0) return TRUE;
        CreateThread(NULL, 0, MainThread, NULL, 0, NULL);
    }
    else if (reason == DLL_PROCESS_DETACH) {
        if (g_Log) { fclose(g_Log); g_Log = nullptr; }
    }
    return TRUE;
}
