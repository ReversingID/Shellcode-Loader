# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `InitOnceExecuteOnce`.

```c++
BOOL InitOnceExecuteOnce (PINIT_ONCE InitOnce, PINIT_ONCE_FN InitFn, PVOID Parameter, LPVOID *Context);
```

### Reference 

- [MSDN InitOnceExecuteOnce](https://docs.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-initonceexecuteonce)