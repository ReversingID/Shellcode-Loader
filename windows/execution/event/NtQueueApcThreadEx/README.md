# Shellcode Loader

Executing shellcode by queueing into APC (Asynchronous Procedure Call).

### Overview

Eksekusi shellcode dengan `NtQueueApcThreadEx`.

```c++
NTSTATUS
NtQueryApcThreadEx (HANDLE ThreadHandle, USER_APC_OPTION UserApcOption, PPS_APC_ROUTINE ApcRoutine, PVOID SystemArgument1, PVOID SystemArgument2, PVOID SystemArgument3);

NTSTATUS NtTestAlert();
```

### Reference 

- [NTInternals NtTestAlert](http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FAPC%2FNtTestAlert.html)
- [BLOG APC Series: User APC API](https://repnz.github.io/posts/apc/user-apc/)