/*
 * CDGuardCancel v1.1 — Guard Cancel During Attacks
 *
 * Dual-signal combat detection:
 * - Requires BOTH: recent RB/RT press AND an evaluator with activeFlag=1
 * - This prevents non-combat RB uses (fire lighting, flash, shops) from
 *   triggering the mod
 * - Idle + LB: don't force → natural clean guard
 * - Combat + LB: force all slot 0 / candCount 3 → guard cancel works
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
static volatile uint8_t g_LBHeld = 0;
static volatile uint8_t g_AttackHeld = 0;     // RB or RT currently held
static volatile DWORD g_LastAttackTick = 0;   // last time RB or RT was pressed
static volatile DWORD g_LastActiveTick = 0;   // last time an evaluator had activeFlag=1
static volatile uint32_t g_ForceCount = 0;
static volatile uint32_t g_CallCount = 0;
static volatile DWORD g_CombatTimeoutMs = 2000;

static bool g_Enabled = true;
static bool g_LogEnabled = true;

static DWORD WINAPI PollThread(LPVOID) {
    XINPUT_STATE state;
    while (true) {
        Sleep(2);
        if (XInputGetState(0, &state) == ERROR_SUCCESS) {
            g_LBHeld = (state.Gamepad.wButtons & XINPUT_GAMEPAD_LEFT_SHOULDER) ? 1 : 0;
            // Track attack buttons: RB (light attack) and RT (heavy attack)
            bool rbHeld = (state.Gamepad.wButtons & XINPUT_GAMEPAD_RIGHT_SHOULDER) != 0;
            bool rtHeld = state.Gamepad.bRightTrigger > 128;
            g_AttackHeld = (rbHeld || rtHeld) ? 1 : 0;
            if (rbHeld || rtHeld) {
                g_LastAttackTick = GetTickCount();
            }
        } else {
            g_LBHeld = 0;
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

    // Track evaluators with active transitions (combat state)
    if (activeFlag != 0) {
        g_LastActiveTick = GetTickCount();
    }

    // Dual-signal combat detection:
    // 1. Player recently pressed RB/RT (attack buttons)
    // 2. At least one evaluator has activeFlag=1 (transition is playing)
    // Both must be true — prevents non-combat RB (fire, flash, shops) from triggering
    DWORD now = GetTickCount();
    bool recentAttack = (now - g_LastAttackTick) < g_CombatTimeoutMs;
    bool hasActiveEval = (now - g_LastActiveTick) < 500;
    bool attackNotHeld = (g_AttackHeld == 0);  // RB/RT not currently pressed
    // All three must be true: recently attacked, combat eval active, attack button released
    // This prevents flash (LB+RB simultaneous) and non-combat RB from triggering
    bool isAttacking = recentAttack && hasActiveEval && attackNotHeld;

    if (retVal == 0 && g_LBHeld && g_Enabled && isAttacking &&
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
    if (g_CombatTimeoutMs < 500) g_CombatTimeoutMs = 500;
    if (g_CombatTimeoutMs > 10000) g_CombatTimeoutMs = 10000;
    GetPrivateProfileStringA("Debug", "LogEnabled", "0", buf, sizeof(buf), iniPath);
    TrimValue(buf); g_LogEnabled = (atoi(buf) != 0);
}

static DWORD WINAPI MainThread(LPVOID) {
    char logPath[MAX_PATH];
    GetModuleFileNameA(NULL, logPath, MAX_PATH);
    char* sl = strrchr(logPath, '\\');
    if (sl) strcpy(sl + 1, "CDGuardCancel.log");
    g_Log = fopen(logPath, "w");

    Log("CDGuardCancel v1.1.1 — Guard Cancel (Triple-Signal Combat Detect)");
    LoadINI();
    Log("Config: Enabled=%d CombatTimeout=%ums LogEnabled=%d", g_Enabled, g_CombatTimeoutMs, g_LogEnabled);
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

    Log("Hook installed! No setup needed.");
    Log("Idle LB = clean guard (no forcing)");
    Log("After RB/RT + LB = forced guard cancel (2s window)");

    uint32_t lastForce = 0, lastCalls = 0;
    while (true) {
        Sleep(3000);
        // Hot-reload INI every 3 seconds
        LoadINI();
        uint32_t calls = g_CallCount, forces = g_ForceCount;
        bool atk = (GetTickCount() - g_LastAttackTick) < g_CombatTimeoutMs;
        if (g_LogEnabled && (calls > lastCalls || forces > lastForce)) {
            Log("calls=%u(+%u) forces=%u(+%u) timeout=%ums attacking=%d LB=%d",
                calls, calls-lastCalls, forces, forces-lastForce,
                g_CombatTimeoutMs, atk ? 1 : 0, g_LBHeld);
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
