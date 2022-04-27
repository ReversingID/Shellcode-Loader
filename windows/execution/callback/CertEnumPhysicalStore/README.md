# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `CertEnumPhysicalStore`.

```c++
BOOL CertEnumPhysicalStore (const void *pvSystemStore, DWORD dwFlags, void *pvArg, PFN_CERT_ENUM_PHYSICAL_STORE pfnEnum);
```

### Reference 

- [MSDN CertEnumPhysicalStore](https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certenumphysicalstore)