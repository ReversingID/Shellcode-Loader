# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `PageSetupDlg`.

```c++
BOOL PageSetupDlg (LPPAGESETUPDLG lpcf);
```

### Reference 

- [MSDN PageSetupDlg](https://docs.microsoft.com/en-us/previous-versions/windows/desktop/legacy/ms646937(v=vs.85))
- [MSDN structure PAGESETUPDLGA](https://docs.microsoft.com/en-us/windows/win32/api/commdlg/ns-commdlg-pagesetupdlga)
- [MSDN structure PAGESETUPDLGW](https://docs.microsoft.com/en-us/windows/win32/api/commdlg/ns-commdlg-pagesetupdlgw)