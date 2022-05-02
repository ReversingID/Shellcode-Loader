# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `GrayString`.

```c++
BOOL GrayStringA (HDC hDC, HBRUSH hBrush, GRAYSTRINGPROC lpOutputFunc, LPARAM lpData, int nCount, int X, int Y, int nWidth, int nHeight);

BOOL GrayStringW (HDC hDC, HBRUSH hBrush, GRAYSTRINGPROC lpOutputFunc, LPARAM lpData, int nCount, int X, int Y, int nWidth, int nHeight);
```

### Reference 

- [MSDN GrayStringA](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-graystringa)
- [MSDN GrayStringW](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-graystringw)