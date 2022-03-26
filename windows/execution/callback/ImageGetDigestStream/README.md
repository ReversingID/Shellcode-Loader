# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `ImageGetDigestStream`.

```c++
BOOL IMAGEAPI ImageGetDigestStream (HANDLE FileHandle, DWORD DigestLevel, DIGEST_FUNCTION DigestFunction, DIGEST_HANDLE DigestHandle);
```

### Reference 

- [MSDN ImageGetDigestStream](https://docs.microsoft.com/en-us/windows/win32/api/imagehlp/nf-imagehlp-imagegetdigeststream)