# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `GetOpenFileName`.

```c++
BOOL GetOpenFileNameA (LPOPENFILENAMEA param);

BOOL GetOpenFileNameW (LPOPENFILENAMEW param);
```

### Reference 

- [MSDN GetOpenFileNameA](https://docs.microsoft.com/en-us/windows/win32/api/commdlg/nf-commdlg-getopenfilenamea)
- [MSDN GetOpenFileNameW](https://docs.microsoft.com/en-us/windows/win32/api/commdlg/nf-commdlg-getopenfilenamew)
- [MSDN structure OPENFILENAMEA](https://docs.microsoft.com/en-us/windows/win32/api/commdlg/ns-commdlg-openfilenamea)
- [MSDN structure OPENFILENAMEW](https://docs.microsoft.com/en-us/windows/win32/api/commdlg/ns-commdlg-openfilenamew)