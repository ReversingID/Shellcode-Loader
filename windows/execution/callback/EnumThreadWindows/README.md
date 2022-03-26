# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `EnumThreadWindows`.

```c++
BOOL EnumThreadWindows (DWORD dwThreadId, WNDENUMPROC lpfn, LPARAM lParam);
```

### Reference 

- [MSDN EnumThreadWindows](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-enumthreadwindows)