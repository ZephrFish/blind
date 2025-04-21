# Blind BOF

This project provides a Beacon Object File (BOF) that implements stealth patching for AMSI, ETW, and Sysmon (NtTraceEvent) using trampoline hooks. It is designed for use in Cobalt Strike to evade detection and suppress telemetry during red team operations.

## Features

- AMSI bypass via trampoline hook on `AmsiScanBuffer`
- ETW patch via trampoline hook on `EtwEventWrite`
- Sysmon blinding by patching `NtTraceEvent`
- BOF-safe memory operations using direct syscalls
- Granular patching support (AMSI / ETW / Sysmon individually)
- Console command integration via `.cna` script
- Detection and confirmation of hook status

## Usage

### BOF Commands

The BOF accepts a single integer argument that determines the action to perform:

| Argument | Description                      |
|----------|----------------------------------|
| `0`      | Patch AMSI, ETW, and Sysmon      |
| `1`      | Patch AMSI only                  |
| `2`      | Patch ETW only                   |
| `3`      | Patch Sysmon (`NtTraceEvent`)    |
| `4`      | Check patch status of all hooks  |

### Cobalt Strike CNA Aliases

Use the `blind` command to trigger actions:

```bash
blind patch     # Patch AMSI, ETW, and Sysmon
blind amsi      # Patch AMSI only
blind etw       # Patch ETW only
blind sysmon    # Patch NtTraceEvent only
blind check     # Check current hook/patch status
```

Files
- bofblind.c - Core BOF source code
- bofblind.x64.o - Compiled x64 BOF object
- blind.cna - Cobalt Strike Aggressor script with aliases and command handler

Compilation

Simply use the `Makefile` with `make` to build the BOF.

Compile using `x86_64-w64-mingw32-gcc` or `llvm-mingw with -c -o bofblind.x64.o bofblind.c` and ensure Beacon-compatible structure and syscall stubs are included. 

Notes

- Only supports x64 Beacons
- No external dependencies
- Requires amsi.dll to be loaded in the target process for AMSI patching

