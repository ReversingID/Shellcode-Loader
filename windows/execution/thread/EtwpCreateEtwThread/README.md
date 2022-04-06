# Shellcode Loader

Executing shellcode as a thread.

### Overview

Eksekusi shellcode dengan `EtwpCreateEtwThread` dan tunggu hingga eksekusi tuntas dengan `WaitForSingleObject`.

`EtwpCreateEtwThread` adalah fungsi internal dan bersifat low-level.

```c++
HANDLE EtwpCreateEtwThread (LPVOID routine, LPVOID param);

DWORD WaitForSingleObject (HANDLE hHandle, DWORD dwMilliseconds);
```

### Reference 

- [NTInternals EtwpCreateEtwThread](https://www.geoffchappell.com/studies/windows/win32/ntdll/api/etw/index.htm)
- [MSDN WaitForSingleObject](https://docs.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject)
- [GIST TheWover](https://gist.github.com/TheWover/b2b2e427d3a81659942f4e8b9a978dc3)