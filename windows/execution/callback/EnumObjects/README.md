# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `EnumObjects`.

```c++
int EnumObjects (HDC hdc, int nType, GOBJENUMPROC lpFunc, LPARAM lParam);
```

### Reference 

- [MSDN EnumObjects](https://docs.microsoft.com/en-us/windows/win32/api/wingdi/nf-wingdi-enumobjects)