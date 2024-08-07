# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `EnumMetaFile`.

```c++
BOOL EnumMetaFile(HDC hdc, HMETAFILE hmf, MFENUMPROC proc, LPARAM param);
```

### Reference 

- [MSDN EnumMetaFile](https://learn.microsoft.com/en-us/windows/win32/api/wingdi/nf-wingdi-enummetafile)