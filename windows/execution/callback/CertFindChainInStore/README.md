# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `CertFindChainInStore`.

```c++
PCCERT_CHAIN_CONTEXT CertFindChainInStore (HCERTSTORE hCertStore, DWORD dwCertEncodingType, DWORD dwFindFlags, DWORD dwFindType, const void *pvFindPara, PCCERT_CHAIN_CONTEXT pPrevChainContext);

HCERTSTORE CertOpenStore (LPCSTR lpszStoreProvider, DWORD dwEncodingType, HCRYPTPROV_LEGACY hCryptProv, DWORD dwFlags, const void *pvPara);

HCERTSTORE CertOpenSystemStoreA (HCRYPTPROV_LEGACY hProv, LPCSTR szSubsystemProtocol);

HCERTSTORE CertOpenSystemStoreW (HCRYPTPROV_LEGACY hProv, LPCWSTR szSubsystemProtocol);
```

### Reference 

- [MSDN CertFindChainInStore](https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certfindchaininstore)
- [MSDN CertOpenStore](https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certopenstore)
- [MSDN CertOpenSystemStoreA](https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certopensystemstorea)
- [MSDN CertOpenSystemStoreW](https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certopensystemstorew)