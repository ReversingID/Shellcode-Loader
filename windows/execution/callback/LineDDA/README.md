# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `LineDDA`.

```c++
BOOL LineDDA(int xStart, int yStart, int xEnd, int yEnd, LINEDDAPROC lpProc, LPARAM data);
```

### Reference 

- [MSDN LineDDA](https://docs.microsoft.com/en-us/windows/win32/api/wingdi/nf-wingdi-linedda)