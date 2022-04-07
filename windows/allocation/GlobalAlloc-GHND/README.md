# Shellcode Loader

Allocate memory for executing shellcode later.

### Overview

Alokasi menggunakan `GlobalAlloc` dan dapatkan handle ke area yang telah dialokasikan. Alamat buffer diperoleh melalui `GlobalLock`.

```c++
HGLOBAL GlobalAlloc (UINT uFlags, SIZE_T dwBytes);

LPVOID GlobalLock (HGLOBAL hMem);

BOOL GlobalUnlock (HGLOBAL hMem);

HGLOBAL GlobalFree (HGLOBAL hMem);
```

### Reference 

- [MSDN GlobalAlloc](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-globalalloc)
- [MSDN GlobalLock](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-globallock)
- [MSDN GlobalUnlock](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-globalunlock)
- [MSDN GlobalFree](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-globalfree)