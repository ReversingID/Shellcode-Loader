# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `EnumWindows`.

```c++
BOOL EnumWindows (WNDENUMPROC lpEnumFunc, LPARAM lParam);
```

### Reference 

- [MSDN EnumWindows](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-enumwindows)