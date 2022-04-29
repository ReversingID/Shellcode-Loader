# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `CryptEnumOIDFunction`.

```c++
BOOL CryptEnumOIDFunction (DWORD dwEncodingType, LPCSTR pszFuncName, LPCSTR pszOID, DWORD dwFlags, void *pvArg, PFN_CRYPT_ENUM_OID_FUNC pfnEnumOIDFunc);
```

### Reference 

- [MSDN CryptEnumOIDFunction](https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptenumoidfunction)