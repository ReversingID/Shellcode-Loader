# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `PrintDlg`.

```c++
BOOL PrintDlg (LPPRINTDLG lppd);
```

### Reference 

- [MSDN PrintDlg](https://docs.microsoft.com/en-us/previous-versions/windows/desktop/legacy/ms646940(v=vs.85))
- [MSDN structure PRINTDLGA](https://docs.microsoft.com/en-us/windows/win32/api/commdlg/ns-commdlg-printdlga)
- [MSDN structure PRINTDLGW](https://docs.microsoft.com/en-us/windows/win32/api/commdlg/ns-commdlg-printdlgW)