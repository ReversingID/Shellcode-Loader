# Shellcode Loader

Executing shellcode as a thread.

### Overview

Eksekusi shellcode dengan `CreateRemoteThreadEx` dan tunggu hingga eksekusi tuntas dengan `WaitForSingleObject`.

`CreateRemoteThread` umumnya digunakan untuk menjalankan thread di remote process. Namun thread baru dapat pula dieksekusi di process sendiri dengan memberikan handle `hProcess` bernilai `GetCurrentProcess()`.

Perbedaan antara `CreateRemoteThread` dan `CreateRemoteThreadEx` terletak pada adanya parameter `lpThreadId` yang memungkinkan untuk mendapatkan thread ID dari thread yang baru dipanggil.

```c++
HANDLE CreateRemoteThreadEx (HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList, LPDWORD lpThreadId

);

DWORD WaitForSingleObject (HANDLE hHandle, DWORD dwMilliseconds);
```

### Reference 

- [MSDN CreateRemoteThreadEx](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethreadex)
- [MSDN WaitForSingleObject](https://docs.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject)