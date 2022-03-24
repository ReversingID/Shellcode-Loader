# Shellcode Loader

Executing shellcode by queueing into APC (Asynchronous Procedure Call).

### Overview

Eksekusi shellcode dengan `QueueUserAPC`.

```c++
DWORD QueueUserAPC(PAPCFUNC pfnAPC, HANDLE hThread, ULONG_PTR dwData);

NTSTATUS NtTestAlert();
```

### Reference 

- [MSDN QueueUserAPC](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-queueuserapc)
- [NTInternals NtTestAlert](http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FAPC%2FNtTestAlert.html)