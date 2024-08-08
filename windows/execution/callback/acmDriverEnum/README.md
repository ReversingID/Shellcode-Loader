# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `acmDriverEnum`.

```c++
MMRESULT ACMAPI acmDriverEnum(ACMDRIVERENUMCB fnCallback, DWORD_PTR dwInstance, DWORD fdwEnum);
```

### Reference 

- [MSDN acmDriverEnum](https://learn.microsoft.com/en-us/windows/win32/api/msacm/nf-msacm-acmdriverenum)