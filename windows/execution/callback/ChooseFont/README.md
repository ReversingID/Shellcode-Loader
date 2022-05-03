# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `ChooseFont`.

```c++
BOOL ChooseFont (LPCHOOSEFONT lpcf);
```

### Reference 

- [MSDN ChooseFont](https://docs.microsoft.com/en-us/previous-versions/windows/desktop/legacy/ms646914(v=vs.85))
- [MSDN structure CHOOSEFONTA](https://docs.microsoft.com/en-us/windows/win32/api/commdlg/ns-commdlg-choosefonta)
- [MSDN structure CHOOSEFONTW](https://docs.microsoft.com/en-us/windows/win32/api/commdlg/ns-commdlg-choosefontW)