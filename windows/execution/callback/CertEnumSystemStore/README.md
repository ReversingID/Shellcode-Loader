# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `CertEnumSystemStore`.

```c++
BOOL CertEnumSystemStore (DWORD dwFlags, void pvSystemStoreLocationPara, void pvArg, PFN_CERT_ENUM_SYSTEM_STORE pfnEnum);
```

### Reference 

- [MSDN CertEnumSystemStore](https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certenumsystemstore)