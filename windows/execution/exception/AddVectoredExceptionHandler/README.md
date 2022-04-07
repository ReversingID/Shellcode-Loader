# Shellcode Loader

Abusing exception to run the shellcode.

### Overview

Eksekusi shellcode melalui exception yang telah didaftarkan melalui `AddVectoredExceptionhandler` dan dipicu dengan `RaiseException`.

```c++
PVOID AddVectoredExceptionHandler (ULONG First, PVECTORED_EXCEPTION_HANDLER Handler);

void RaiseException (DWORD dwExceptionCode, DWORD dwExceptionFlags, DWORD nNumberOfArguments, const ULONG_PTR *lpArguments);

ULONG RemoveVectoredExceptionHandler (PVOID Handle);
```

### Reference

- [MSDN AddVectoredExceptionhandler](https://docs.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-addvectoredexceptionhandler)
- [MSDN RaiseException](https://docs.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-raiseexception)
- [MSDN RemoveVectoredExceptionHandler](https://docs.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-removevectoredexceptionhandler)