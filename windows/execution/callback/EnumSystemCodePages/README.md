# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `EnumSystemCodePages`.

```c++
BOOL EnumSystemCodePagesA (CODEPAGE_ENUMPROCA lpCodePageEnumProc, DWORD dwFlags);

BOOL EnumSystemCodePagesW (CODEPAGE_ENUMPROCW lpCodePageEnumProc, DWORD dwFlags);
```

### Reference 

- [MSDN EnumSystemCodePagesA](https://docs.microsoft.com/en-us/windows/win32/api/winnls/nf-winnls-enumsystemcodepagesa)
- [MSDN EnumSystemCodePagesW](https://docs.microsoft.com/en-us/windows/win32/api/winnls/nf-winnls-enumsystemcodepagesw)