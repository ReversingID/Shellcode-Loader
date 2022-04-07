# Shellcode Loader

Allocate memory for executing shellcode later.

### Overview

Alokasi menggunakan `AllocADsMem`.

```c++
LPVOID AllocADsMem (DWORD cb);

BOOL FreeADsMem (LPVOID pMem);
```

### Reference 

- [MSDN AllocADsMem](https://docs.microsoft.com/en-us/windows/win32/api/adshlp/nf-adshlp-allocadsmem)
- [MSDN FreeADsMem](https://docs.microsoft.com/en-us/windows/win32/api/adshlp/nf-adshlp-freeadsmem)