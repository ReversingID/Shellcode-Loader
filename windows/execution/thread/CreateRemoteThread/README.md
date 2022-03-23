# Shellcode Loader

Executing shellcode as a thread.

### Overview

Eksekusi shellcode dengan `CreateRemoteThread` dan tunggu hingga eksekusi tuntas dengan `WaitForSingleObject`.

`CreateRemoteThread` umumnya digunakan untuk menjalankan thread di remote process. Namun thread baru dapat pula dieksekusi di process sendiri dengan memberikan handle `hProcess` bernilai `GetCurrentProcess()`.

```c++
HANDLE CreateRemoteThread (HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);

DWORD WaitForSingleObject (HANDLE hHandle, DWORD dwMilliseconds);
```

### Reference 

- [MSDN CreateRemoteThread](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread)
- [MSDN WaitForSingleObject](https://docs.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject)