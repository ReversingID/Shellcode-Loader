# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `CryptVerifyMessageSignature`.

```c++
BOOL CryptVerifyMessageSignature (PCRYPT_VERIFY_MESSAGE_PARA pVerifyPara, DWORD dwSignerIndex, const BYTE *pbSignedBlob, DWORD cbSignedBlob, BYTE *pbDecoded, DWORD *pcbDecoded, PCCERT_CONTEXT *ppSignerCert);
```

### Reference 

- [MSDN CryptVerifyMessageSignature](https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptverifymessagesignature)
- [MSDN structure CRYPT_VERIFY_MESSAGE_PARA](https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-crypt_verify_message_para)