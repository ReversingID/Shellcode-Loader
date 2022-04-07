# Shellcode Loader

Abusing exception to run the shellcode.

### Overview

Eksekusi shellcode melalui exception yang telah didaftarkan melalui `SetUnhandledExceptionFilter` dan dipicu dengan sembarang exception.

```c++
LPTOP_LEVEL_EXCEPTION_FILTER SetUnhandledExceptionFilter (LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter);
```

### Reference

- [MSDN SetUnhandledExceptionFilter](https://docs.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-setunhandledexceptionfilter)