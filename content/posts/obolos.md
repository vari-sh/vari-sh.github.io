# 🪙 Obolos: Building a Polymorphic Syscall Engine with Full Stack Spoofing

> **Disclaimer.** This material is published for educational and research purposes only. Understanding offensive techniques is essential for building better defenses. The author assumes no responsibility for misuse.

**Tags:** Indirect Syscalls · Stack Spoofing · Halo's Gate · Polymorphic Stubs · x64 Windows

---

## 01 — Threat Model and Motivation

Modern Endpoint Detection and Response (EDR) solutions on Windows operate primarily by hooking `ntdll.dll` — intercepting every call before it reaches the kernel, inspecting arguments, and flagging suspicious behavior. Bypassing this layer requires invoking kernel services directly, without ever touching user-space hooks. This post walks through the full architecture of a custom syscall engine that combines **indirect syscalls**, **extended stack spoofing**, **dynamic SSN resolution** via Halo's Gate, and **polymorphic stub generation** to produce a stealthy, robust call dispatcher.

EDR products typically inject a monitoring DLL into every new process. That DLL patches the first few bytes of sensitive `Nt*` functions inside `ntdll.dll` with a `jmp` to an inspection trampoline. When your code calls, say, `NtAllocateVirtualMemory`, it silently detours through the vendor's hook before (or instead of) reaching the real kernel gate.

There are three classical responses to this problem:

| Technique         | Mechanism                                           | Weakness                                                    |
| ----------------- | --------------------------------------------------- | ----------------------------------------------------------- |
| Direct Syscalls   | Inline `mov r10, rcx; syscall` in your binary       | Callstack doesn't originate from ntdll — easy to flag       |
| Unhooking         | Re-map a clean `ntdll.dll` from disk                | Suspicious file I/O; detected by IAT / module monitoring    |
| Indirect Syscalls | Jump to the real `syscall; ret` gadget inside ntdll | Incomplete alone — stack still looks wrong without spoofing |

This engine adopts the indirect syscall approach and solves its remaining weakness — the suspicious call stack — through synthetic stack construction at the moment of the call.

---

## 02 — High-Level Architecture

The engine is split across four layers that collaborate at runtime:

**1. Initialization (`engine.c`)**
Parses the export table of `ntdll.dll`, extracts SSNs with Halo's Gate, locates real `syscall; ret` gadgets, finds a `jmp REG` gadget for the spoofing pivot, and computes spoofing masks dynamically by scanning live module code.

**2. ASM Core (`syscalls_base.asm`)**
A single `SyscallExec` routine that aligns the stack, synthesizes a completely fake-but-plausible call stack, copies arguments, then performs the indirect syscall jump.

**3. Polymorphic Stubs (`generate_stubs.py`)**
A Python script generates 512 individual MASM stub functions, each 16 bytes wide, loading their own index and jumping to `SyscallExec`. Random junk bytes inside each stub break block-hash signatures.

**4. Caller Interface (`engine.h` + `main.c`)**
A macro-based API lets callers resolve any `Nt*` function by djb2 hash, map it to its stub, and dispatch it with a chosen spoofing mask — all in a few lines.

---

## 03 — SSN Resolution: Halo's Gate

The System Service Number (SSN) is the integer that identifies a syscall to the Windows kernel. In a clean `ntdll.dll`, every `Nt*` stub begins with a predictable prologue:

```asm
mov  r10, rcx           ; 4C 8B D1
mov  eax, 0x0060        ; B8 60 00 00 00  ← SSN here
syscall
ret
```

If a hook is present, the first few bytes of the stub are overwritten with a `jmp` and the SSN is no longer readable at offset +4. The engine's `GetSSN()` function handles this with a **neighbor-scan**: if a function is hooked, it looks at adjacent stubs (which are spaced 32 bytes apart) to find an intact one, then adjusts the returned SSN by the distance walked:

```c
DWORD64 GetSSN(PVOID pAddress) {
    if (*(PBYTE)pAddress       == 0x4c &&
        *(PBYTE)(pAddress + 3) == 0xb8)
        return *(DWORD*)((PBYTE)pAddress + 4);   // Direct read

    for (WORD idx = 1; idx <= 32; idx++) {
        // Neighbor below (higher SSN)
        if (*(PBYTE)(pAddress + idx*32) == 0x4c &&
            *(PBYTE)(pAddress + idx*32 + 3) == 0xb8)
            return *(PBYTE)(pAddress + idx*32 + 4) - idx;
        // Neighbor above (lower SSN)
        if (*(PBYTE)(pAddress - idx*32) == 0x4c &&
            *(PBYTE)(pAddress - idx*32 + 3) == 0xb8)
            return *(PBYTE)(pAddress - idx*32 + 4) + idx;
    }
    return INVALID_SSN;
}
```

The function also uses `GetNextSyscallInstruction()` to locate the actual `0F 05 C3` byte sequence (`syscall; ret`) within the unhooked body of ntdll — this is the target address for the indirect jump that happens later.

---

## 04 — Gadget Discovery

The indirect syscall trick requires that the CPU's instruction pointer live inside ntdll when the kernel interrupt fires. Naively, one would `call` into ntdll — but that would put your own code on the return address. Instead, the engine pivots via a *register-indirect jump* gadget: an instruction like `jmp rbx` or `jmp r14` that exists naturally inside `kernel32.dll`.

`FindValidGadgetInModule()` walks every executable section of the target module, scanning byte-by-byte for the seven supported opcode patterns:

| Type ID | Bytes      | Instruction |
| ------- | ---------- | ----------- |
| 0       | `FF E3`    | `jmp rbx`   |
| 1       | `FF E7`    | `jmp rdi`   |
| 2       | `FF E6`    | `jmp rsi`   |
| 3       | `41 FF E4` | `jmp r12`   |
| 4       | `41 FF E5` | `jmp r13`   |
| 5       | `41 FF E6` | `jmp r14`   |
| 6       | `41 FF E7` | `jmp r15`   |

Crucially, the gadget must belong to a function with a sufficiently large stack frame (≥ `0x100` bytes). This is checked via `CalcFrameSize()`, which reads the function's `.pdata` section entry via `RtlLookupFunctionEntry` and parses every unwind code to sum up the total frame allocation. This ensures the spoofed frame is large enough to look natural and not trigger heuristics based on implausibly small intermediate frames.

---

## 05 — Dynamic Spoofing Masks

A "mask" is a (return address, frame size) pair that represents a believable intermediate frame in the synthesized call stack. Previous implementations hardcoded offsets like `pFunc + 0x4B` — fragile across Windows updates and easily fingerprinted.

This engine resolves masks at runtime using `SeekReturnAddress()`. Given a function pointer, it scans the function body for either a `CALL QWORD PTR [RIP+offset]` (`FF 15`) or a relative `CALL` (`E8`) instruction, and returns the address of the byte *immediately after* that call — which is exactly where the CPU would push a return address during normal execution.

```c
PVOID SeekReturnAddress(PVOID pBase) {
    PBYTE pBytes = (PBYTE)pBase;
    for (int i = 0; i < 256; i++) {
        if (pBytes[i] == 0xFF && pBytes[i+1] == 0x15)
            return (PVOID)(pBytes + i + 6);   // After FF15 xxxxxxxx
        if (pBytes[i] == 0xE8)
            return (PVOID)(pBytes + i + 5);   // After E8 xxxxxxxx
    }
    return pBase; // Fallback
}
```

Four named masks are preloaded at initialization, each anchored to a familiar Win32 API:

| Mask            | Anchor function    | Intended use                           |
| --------------- | ------------------ | -------------------------------------- |
| `Mask_Memory`   | `MapViewOfFile`    | Memory allocation / mapping operations |
| `Mask_File`     | `MoveFileW`        | File I/O operations                    |
| `Mask_Security` | `VirtualProtectEx` | Permission / protection changes        |
| `Mask_Worker`   | `CreateProcessW`   | Thread / synchronization operations    |

---

## 06 — The ASM Core: `SyscallExec`

This is the heart of the engine. When any stub calls into `SyscallExec`, the following sequence executes.

### Step 1 — Save incoming registers

The Windows x64 calling convention passes the first four arguments in `rcx`, `rdx`, `r8`, `r9`. Since we'll be manipulating `rsp` and other registers, all four are saved in the caller's shadow space before anything moves.

### Step 2 — Synthesize the fake stack

The real `rsp` is saved in `qSavedRetAddr`. Then `rsp` is aligned to 16 bytes and decremented by a dynamically computed total size — the sum of four frame sizes, each with an 8-byte return address slot above it:

```
┌───────────────────────────────────────────────┐
│  [real RSP]  → saved, will be restored later  │
├───────────────────────────────────────────────┤
│  qFrameSize bytes   (gadget's frame)          │
│  + 8 bytes  ← qActiveMaskAddress (return adr) │
│  qActiveMaskFrame bytes (mask frame)          │
│  + 8 bytes  ← qThreadBase (return address)    │
│  qThreadBaseFrame bytes (BaseThreadInitThunk) │
│  + 8 bytes  ← qRtlUserThreadStart             │
│  qRtlUserThreadStartFrame bytes               │
│  + 8 bytes  ← NULL (top of thread sentinel)   │
└───────────────────────────────────────────────┘
↑ RSP after spoofing
```

The result is a stack that — when unwound by a debugger or an EDR's telemetry engine — looks exactly like a thread that legitimately called from `RtlUserThreadStart → BaseThreadInitThunk → [Win32 API mask] → syscall`. There is no trace of the real caller anywhere on the visible stack.

### Step 3 — Copy stack arguments

Syscalls with more than four arguments require additional values on the stack (in the "home space" above the shadow space). The engine uses a `rep movsq` to copy 8 QWORDs from the original `rsp+0x28` to the new `rsp+0x20`, transplanting any extra arguments into their correct positions on the synthetic stack.

### Step 4 — Dynamic gadget dispatch

The chosen gadget register is loaded with the address of the `BackFromKernel` label. The gadget address is pushed onto the stack as the apparent return address from the syscall. Then a `jmp r11` fires, where `r11` holds the real `syscall; ret` address inside ntdll.

```asm
DoCall:
    push   rdx               ; Save Arg2
    shl    rax, 5            ; rax *= 32 (sizeof SYSCALL_ENTRY)
    mov    rdx, qTableAddr
    add    rdx, rax
    mov    rax, [rdx + 08h]  ; Load SSN into RAX
    mov    r11, [rdx + 10h]  ; Load syscall;ret address
    pop    rdx               ; Restore Arg2
    mov    rcx, r10          ; Restore Arg1
    push   qGadgetAddress    ; Fake return address (the jmp REG gadget)
    jmp    r11               ; → indirect syscall inside ntdll
```

From the kernel's perspective (and from any call stack walker): the `syscall` instruction executes from within ntdll, the return address on the stack points back into kernel32, and the chain above that traces all the way up to `RtlUserThreadStart`. Perfectly ordinary.

### Step 5 — Cleanup and return

After `BackFromKernel`, the saved register is restored, `rsp` is snapped back to `qSavedRetAddr`, `rsi`/`rdi` are restored from the original shadow space, and `rax` (holding `NTSTATUS`) is returned to the caller.

---

## 07 — Polymorphic Stub Generation

The Python script generates a 512-entry stub table. Every function `Fnc0000` through `Fnc01FF` occupies exactly 16 bytes and has the same structure:

```asm
    ALIGN 16
    Fnc002A PROC
        mov    eax, 2Ah          ; 5 bytes: B8 2A 00 00 00
        jmp    SyscallExec       ; 5 bytes: E9 xxxxxxxx
        xchg   r8, r8            ; 3 bytes: junk
        nop                      ; 1 byte
        nop                      ; 1 byte
        nop                      ; 1 byte  → total 16 bytes
    Fnc002A ENDP
```

The fixed 16-byte stride is the key design choice. It means any caller can compute the address of stub *N* with a single multiplication: `pStubBase + N × 16` — no lookup table required. The random padding (three variants: 6× NOP, `xchg r8,r8` + 3× NOP, 2× `xchg ax,ax` + 2× NOP) ensures that block-hash based signatures cannot match the stub region as a whole, even though every stub is functionally identical.

---

## 08 — Caller API and Usage

The entire complexity above is hidden behind a single macro in `engine.h`:

```c
#define ExecuteSyscall(func_ptr, mask, ...) ( \
    qActiveMaskAddress = (mask).pAddress,     \
    qActiveMaskFrame   = (mask).dwFrameSize,  \
    func_ptr(__VA_ARGS__)                      \
)
```

Before calling the stub, the macro writes the selected mask into two globals. `SyscallExec` reads them via `qActiveMaskAddress` and `qActiveMaskFrame` during the stack synthesis step. The complete flow from `main.c`:

```c
// 1. Find the syscall by hash
DWORD64 hAlloc = djb2((PBYTE)"NtAllocateVirtualMemory");
for (int i = 0; i < SyscallList.Count; i++) {
    if (SyscallList.Entries[i].dwHash == hAlloc) { idxAllocate = i; break; }
}

// 2. Compute the stub address by index
PBYTE pStubBase = (PBYTE)&Fnc0000;
fnNtAllocateVirtualMemory pAlloc =
    (fnNtAllocateVirtualMemory)(pStubBase + (idxAllocate * 16));

// 3. Invoke with the appropriate mask
NTSTATUS status = ExecuteSyscall(pAlloc, Mask_Worker,
    (HANDLE)-1, &pMem, 0, &sSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
```

**Result.** The kernel receives the call with the correct SSN and arguments. The call stack visible to any observer shows `ntdll!NtAllocateVirtualMemory → kernel32!WaitForSingleObjectEx → ntdll!BaseThreadInitThunk → ntdll!RtlUserThreadStart` — a perfectly mundane worker thread calling a synchronization API. There is nothing in the trace that points to the real call site.

---

## 09 — OPSEC Considerations and Limitations

### What this engine does well

The combination of indirect syscalls (RIP inside ntdll) + full synthetic stack unwinding + dynamic mask resolution + randomized stub bytes covers the main detection vectors used by contemporary EDR telemetry: hook interception, stack-origin analysis, and static binary signature matching.

### Remaining attack surface

**Kernel ETW.** `EtwTi` callbacks in the kernel can observe certain syscall events regardless of user-space trickery. Argument sanitization doesn't help here.

**Global variable exposure.** `qSavedRetAddr`, `qActiveMaskAddress`, and similar globals are plain `.data` entries. In a multi-threaded scenario, concurrent syscalls would race on these globals. A TLS-based per-thread context would be required for thread safety.

---

## 10 — Summary

The engine presented here is a self-contained, production-style syscall dispatcher that assembles several well-understood concepts into a single, maintainable codebase:

**Halo's Gate** for hook-resilient SSN extraction → **indirect syscall** via a dynamically discovered ntdll gadget → **extended synthetic stack** constructed from live frame-size data → **dynamic spoofing masks** resolved by scanning real function bodies → **polymorphic 16-byte stubs** generated at build time to break block-hash signatures.

Each technique individually has well-known detection signatures. Together, configured to be self-consistent and dynamically resolved, they raise the detection cost substantially. Understanding how they work at this level is the necessary foundation for both building better offensive tooling and designing the next generation of evasion-aware defenses.

---

*Sources and prior work: SysWhispers3, Hell's Gate / Halo's Gate (am0nsec, RtlMateusz), stack spoofing research (KlezVirus, Waldo-IRC, Trickster0).*
