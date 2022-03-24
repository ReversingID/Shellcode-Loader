# Shellcode Loader

Executing shellcode as a thread.

### Overview

Eksekusi shellcode dengan `RtlCreateUserThread` dan tunggu hingga eksekusi tuntas dengan `WaitForSingleObject`.

`RtlCreateUserThread` adalah fungsi internal dan bersifat low-level.

```c++
NTSTATUS RtlCreateUserThread (HANDLE ProcessHandle, PSECURITY_DESCRIPTOR SecurityDescriptor, BOOLEAN CreateSuspended, ULONG StackZeroBits, PULONG StackReserved, PULONG StackCommit, PVOID StartAddress, PVOID StartParameter, PHANDLE ThreadHandle, PCLIENT_ID ClientID);

DWORD WaitForSingleObject (HANDLE hHandle, DWORD dwMilliseconds);
```

### Reference 

- [NTInternals RtlCreateUserThread](http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FRtlCreateUserThread.html)
- [MSDN WaitForSingleObject](https://docs.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject)