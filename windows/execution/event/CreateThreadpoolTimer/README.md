# Shellcode Loader

Executing shellcode using timer.

### Overview

Eksekusi shellcode dengan `CreateThreadpoolTimer`.

Thread pool adalah sekumpulan worker thread yang mengeksekusi callback secara asinkron.

```c++
PTP_TIMER CreateThreadpoolTimer(PTP_TIMER_CALLBACK pfnti, PVOID pv, PTP_CALLBACK_ENVIRON pcbe);

void SetThreadpoolTimer(PTP_TIMER pti, PFILETIME pftDueTime, DWORD msPeriod, DWORD msWindowLength);

HANDLE CreateEventA(LPSECURITY_ATTRIBUTES lpEventAttributes, BOOL bManualReset, BOOL bInitialState, LPCSTR lpName);

DWORD WaitForSingleObject (HANDLE hHandle, DWORD dwMilliseconds);
```

### Reference 

- [MSDN CreateThreadpoolTimer](https://docs.microsoft.com/en-us/windows/win32/api/threadpoolapiset/nf-threadpoolapiset-createthreadpooltimer)
- [MSDN SetThreadpoolTimer](https://docs.microsoft.com/en-us/windows/win32/api/threadpoolapiset/nf-threadpoolapiset-setthreadpooltimer)
- [MSDN CreateEventA](https://docs.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-createeventa)
- [MSDN WaitForSingleObject](https://docs.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject)