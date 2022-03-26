# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `EnumDesktopWindows`.

```c++
BOOL EnumDesktopWindows (HDESK hDesktop, WNDENUMPROC lpfn, LPARAM lParam);
```

### Reference 

- [MSDN EnumDesktopWindows](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-enumdesktopwindows)