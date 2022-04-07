# Shellcode Loader

Allocate memory for executing shellcode later.

### Overview

Alokasi menggunakan `GlobalAlloc` dan dapatkan pointer ke area yang telah dialokasikan.

```c++
HGLOBAL GlobalAlloc (UINT uFlags, SIZE_T dwBytes);

HGLOBAL GlobalFree (HGLOBAL hMem);
```

### Reference 

- [MSDN GlobalAlloc](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-globalalloc)
- [MSDN GlobalFree](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-globalfree)