# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `GetSaveFileName`.

```c++
BOOL GetSaveFileNameA (LPOPENFILENAMEA param);

BOOL GetSaveFileNameW (LPOPENFILENAMEW param);
```

### Reference 

- [MSDN GetSaveFileNameA](https://docs.microsoft.com/en-us/windows/win32/api/commdlg/nf-commdlg-getsavefilenamea)
- [MSDN GetSaveFileNameW](https://docs.microsoft.com/en-us/windows/win32/api/commdlg/nf-commdlg-getsavefilenamew)
- [MSDN structure OPENFILENAMEA](https://docs.microsoft.com/en-us/windows/win32/api/commdlg/ns-commdlg-openfilenamea)
- [MSDN structure OPENFILENAMEW](https://docs.microsoft.com/en-us/windows/win32/api/commdlg/ns-commdlg-openfilenamew)