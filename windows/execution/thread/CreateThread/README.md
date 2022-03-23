# Shellcode Loader

Executing shellcode as a thread.

### Overview

Eksekusi shellcode dengan `CreateThread` dan tunggu hingga eksekusi tuntas dengan `WaitForSingleObject`.

```c++
HANDLE CreateThread (LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, __drv_aliasesMem LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);

DWORD WaitForSingleObject (HANDLE hHandle, DWORD dwMilliseconds);
```

### Reference 

- [MSDN CreateThread](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread)
- [MSDN WaitForSingleObject](https://docs.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject)