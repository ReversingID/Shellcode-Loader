# Shellcode Loader

Executing shellcode as a thread.

### Overview

Eksekusi shellcode dengan `NtCreateThreadEx` dan tunggu hingga eksekusi tuntas dengan `WaitForSingleObject`.

`NtCreateThreadEx` adalah fungsi internal dan bersifat low-level.

```c++
NTSTATUS NtCreateThreadEx (PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, HANDLE ProcessHandle, PVOID lpStartAddress, PVOID lpParameter, ULONG flags, SIZE_T szStackZeroBits, SIZE_T szStackCommitSize, SIZE_T szStackReserveSize, PVOID lpBytesBuffer);

DWORD WaitForSingleObject (HANDLE hHandle, DWORD dwMilliseconds);
```

### Reference 

- [NTInternals NtCreateThreadEx](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethreadex)
- [MSDN WaitForSingleObject](https://docs.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject)