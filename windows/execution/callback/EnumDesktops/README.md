# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `EnumDesktops`.

```c++
BOOL EnumDesktopsA (HWINSTA hwinsta, DESKTOPENUMPROCA lpEnumFunc, LPARAM lParam);

BOOL EnumDesktopsW (HWINSTA hwinsta, DESKTOPENUMPROCW lpEnumFunc, LPARAM lParam);
```

### Reference 

- [MSDN EnumDesktopA](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-enumdesktopsa)
- [MSDN EnumDesktopW](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-enumdesktopsw)