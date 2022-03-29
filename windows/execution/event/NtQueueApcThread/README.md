# Shellcode Loader

Executing shellcode by queueing into APC (Asynchronous Procedure Call).

### Overview

Eksekusi shellcode dengan `NtQueueApcThread`.

```c++
NTSTATUS NtQueueApcThread (HANDLE ThreadHandle, PIO_APC_ROUTINE ApcRoutine, PVOID ApcRoutineContext, PIO_STATUS_BLOCK ApcStatusBlock, ULONG ApcReserved);

NTSTATUS NtTestAlert();
```

### Reference 

- [MSDN NtQueueApcThread](http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FAPC%2FNtQueueApcThread.html)
- [NTInternals NtTestAlert](http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FAPC%2FNtTestAlert.html)
- [BLOG APC Series: User APC API Low Level Pleasure](https://repnz.github.io/posts/apc/user-apc/)