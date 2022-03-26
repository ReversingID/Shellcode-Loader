# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `EnumChildWindows`.

```c++
BOOL EnumChildWindows(HWND hWndParent, WNDENUMPROC lpEnumFunc, LPARAM lParam);
```

### Reference 

- [MSDN EnumChildWindows](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-enumchildwindows)