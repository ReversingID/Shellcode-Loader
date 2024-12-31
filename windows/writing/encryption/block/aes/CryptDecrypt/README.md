# Shellcode Loader

Shellcode encryption.

### Overview

Enkripsi AES menggunakan fungsi `CryptEncrypt` dan dekripsi dengan `CryptDecrypt`.

Fungsi ini termasuk deprecated dan disarankan untuk menggunakan API `Cryptographic Next Generation`.

```c++
BOOL CryptEncrypt (HCRYPTKEY hKey, HCRYPTHAS hHash, BOOL Final, DWORD dwFlags, BYTE *pbData, DWORD *pdwDataLen, DWORD dwBufLen);

BOOL CryptDecrypt (HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE *pbData, DWORD *pdwDataLen);

BOOL CryptAcquireContextA (HCRYPTPROV *phProv, LPCSTR  szContainer, LPCSTR szProvider, DWORD dwProvType, DWORD dwFlags);

BOOL CryptAcquireContextW (HCRYPTPROV *phProv, LPCWSTR  szContainer, LPCWSTR szProvider, DWORD dwProvType, DWORD dwFlags);

BOOL CryptHashData (HCRYPTHASH hHash, const BYTE *pbData, DWORD dwDataLen, DWORD dwFlags);

BOOL CryptDeriveKey( HCRYPTPROV hProv, ALG_ID Algid, HCRYPTHASH hBaseData, DWORD dwFlags, HCRYPTKEY *phKey);

BOOL CryptDestroyKey (HCRYPTKEY hKey);

BOOL CryptDestroyHash (HCRYPTHASH hHash);

BOOL CryptReleaseContext (HCRYPTPROV hProv, DWORD dwFlags);
```

### Reference

- [MSDN CryptEncrypt](https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptencrypt)
- [MSDN CryptDecrypt](https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptdecrypt)
- [MSDN CryptAcquireContextA](https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontexta)
- [MSDN CryptAcquireContextW](https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontextw)
- [MSDN CryptHashData](https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-crypthashdata)
- [MSDN CryptDeriveKey](https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptderivekey)
- [MSDN ALG_ID algorithm list](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)
- [MSDN CryptDestroyKey](https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptdestroykey)
- [MSDN CryptDestroyHash](https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptdestroyhash)
- [MSDN CryptReleaseContext](https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptreleasecontext)