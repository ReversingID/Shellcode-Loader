# Shellcode Loader

Executing shellcode as a thread.

### Overview

Eksekusi shellcode dengan `CreateThreadpoolWait`.

Thread pool adalah sekumpulan worker thread yang mengeksekusi callback secara asinkron.

```c++
PTP_WAIT CreateThreadpoolWait(PTP_WAIT_CALLBACK pfnwa, PVOID pv, PTP_CALLBACK_ENVIRON pcbe);

void SetThreadpoolWait(PTP_WAIT pwa, HANDLE h, PFILETIME pftTimeout);

HANDLE CreateEventA(LPSECURITY_ATTRIBUTES lpEventAttributes, BOOL bManualReset, BOOL bInitialState, LPCSTR lpName);

DWORD WaitForSingleObject (HANDLE hHandle, DWORD dwMilliseconds);
```

### Reference 

- [MSDN CreateThreadpoolWait](https://docs.microsoft.com/en-us/windows/win32/api/threadpoolapiset/nf-threadpoolapiset-createthreadpoolwait)
- [MSDN SetThreadpoolWait](https://docs.microsoft.com/en-us/windows/win32/api/threadpoolapiset/nf-threadpoolapiset-setthreadpoolwait)
- [MSDN CreateEventA](https://docs.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-createeventa)
- [MSDN WaitForSingleObject](https://docs.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject)