# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `CryptInstallOIDFunctionAddress`.

Install fungsi sebagai callback saat membuka store baru.

```c++
BOOL CryptInstallOIDFunctionAddress(HMODULE hModule, DWORD dwEncodingType, LPCSTR pszFuncName, DWORD cFuncEntry, const CRYPT_OID_FUNC_ENTRY [] rgFuncEntry, DWORD dwFlags);

BOOL CryptFreeOIDFunctionAddress (HCRYPTOIDFUNCADDR hFuncAddr, DWORD dwFlags);

HCERTSTORE CertOpenStore (LPCSTR lpszStoreProvider, DWORD dwEncodingType, HCRYPTPROV_LEGACY hCryptProv, DWORD dwFlags, const void *pvPara);

BOOL CertCloseStore (HCERTSTORE hCertStore, DWORD dwFlags);
```

### Reference 

- [MSDN CryptInstallOIDFunctionAddress](https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptinstalloidfunctionaddress)
- [MSDN CryptFreeOIDFunctionAddress](https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptfreeoidfunctionaddress)
- [MSDN CertOpenStore](https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certopenstore)
- [MSDN CertCloseStore](https://docs.microsoft.com/en-us/windows/win32/api/Wincrypt/nf-wincrypt-certclosestore)
