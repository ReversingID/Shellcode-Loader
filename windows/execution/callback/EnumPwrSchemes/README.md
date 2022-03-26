# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `EnumPwrSchemes`.

```c++
BOOLEAN EnumPwrSchemes (PWRSCHEMESENUMPROC lpfn, LPARAM lParam);
```

### Reference 

- [MSDN EnumPwrSchemes](https://docs.microsoft.com/en-us/windows/win32/api/powrprof/nf-powrprof-enumpwrschemes)