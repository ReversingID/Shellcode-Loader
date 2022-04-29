# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `CryptDecodeMessage`.

```c++
BOOL CryptDecodeMessage (DWORD dwMsgTypeFlags, PCRYPT_DECRYPT_MESSAGE_PARA pDecryptPara, PCRYPT_VERIFY_MESSAGE_PARA pVerifyPara, DWORD dwSignerIndex, const BYTE *pbEncodedBlob, DWORD cbEncodedBlob, DWORD dwPrevInnerContentType, DWORD *pdwMsgType, DWORD *pdwInnerContentType, BYTE *pbDecoded, DWORD *pcbDecoded, PCCERT_CONTEXT *ppXchgCert, PCCERT_CONTEXT *ppSignerCert);
```

### Reference 

- [MSDN CryptDecodeMessage](https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptdecodemessage)
- [MSDN structure CRYPT_VERIFY_MESSAGE_PARA](https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-crypt_verify_message_para)