# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `ImmEnumInputContext`.

```c++
BOOL ImmEnumInputContext (DWORD idThread, IMCENUMPROC lpfn, LPARAM lParam);
```

### Reference 

- [MSDN ImmEnumInputContext](https://docs.microsoft.com/en-us/windows/win32/api/imm/nf-imm-immenuminputcontext)