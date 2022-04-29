# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `CryptEnumKeyIdentifierProperties`.

```c++
BOOL CryptEnumKeyIdentifierProperties (const CRYPT_HASH_BLOB *pKeyIdentifier, DWORD dwPropId, DWORD dwFlags, LPCWSTR pwszComputerName, void *pvReserved, void *pvArg, PFN_CRYPT_ENUM_KEYID_PROP pfnEnum);
```

### Reference 

- [MSDN CryptEnumKeyIdentifierProperties](https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptenumkeyidentifierproperties)