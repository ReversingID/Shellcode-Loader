# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `EnumWindowStations`.

```c++
BOOL EnumWindowStationsA (WINSTAENUMPROCA lpEnumFunc, LPARAM lParam);

BOOL EnumWindowStationsW (WINSTAENUMPROCW lpEnumFunc, LPARAM lParam);
```

### Reference 

- [MSDN EnumWindowStationsA](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-enumwindowstationsa)
- [MSDN EnumWindowStationsW](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-enumwindowstationsw)