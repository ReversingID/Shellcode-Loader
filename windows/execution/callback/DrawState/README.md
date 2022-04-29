# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `DrawState`.

```c++
BOOL DrawStateA (HDC hdc, HBRUSH hbrFore, DRAWSTATEPROC qfnCallBack, LPARAM lData, WPARAM wData, int x, int y, int cx, int cy, UINT uFlags);

BOOL DrawStateW (HDC hdc, HBRUSH hbrFore, DRAWSTATEPROC qfnCallBack, LPARAM lData, WPARAM wData, int x, int y, int cx, int cy, UINT uFlags);
```

### Reference 

- [MSDN DrawStateA](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-drawstatea)
- [MSDN DrawStateW](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-drawstatew)