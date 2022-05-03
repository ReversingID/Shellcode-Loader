# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `ChooseColor`.

```c++
BOOL ChooseColor (LPCHOOSECOLOR lpcc);
```

### Reference 

- [MSDN ChooseColor](https://docs.microsoft.com/en-us/previous-versions/windows/desktop/legacy/ms646912(v=vs.85))
- [MSDN structure CHOOSECOLORA](https://docs.microsoft.com/en-us/windows/win32/api/commdlg/ns-commdlg-choosecolora-r1)
- [MSDN structure CHOOSECOLORW](https://docs.microsoft.com/en-us/windows/win32/api/commdlg/ns-commdlg-choosecolorw-r1)