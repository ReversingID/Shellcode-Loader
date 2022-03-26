# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `CryptEnumOIDInfo`.

```c++
BOOL CryptEnumOIDInfo (DWORD dwGroupId, DWORD dwFlags, void pvArg, PFN_CRYPT_ENUM_OID_INFO pfnEnumOIDInfo);
```

### Reference 

- [MSDN CryptEnumOIDInfo](https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptenumoidinfo)