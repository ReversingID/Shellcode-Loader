# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `CertEnumSystemStoreLocation`.

```c++
BOOL CertEnumSystemStoreLocation (DWORD dwFlags, void * pvArg, PFN_CERT_ENUM_SYSTEM_STORE_LOCATION pfnEnum);
```

### Reference 

- [MSDN CertEnumSystemStoreLocation](https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certenumsystemstorelocation)