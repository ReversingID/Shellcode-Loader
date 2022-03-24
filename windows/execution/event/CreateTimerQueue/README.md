# Shellcode Loader

Executing shellcode using timer.

### Overview

Eksekusi shellcode dengan `CreateTimerQueue` dan `CreateTimerQueueTimer`.

Thread pool adalah sekumpulan worker thread yang mengeksekusi callback secara asinkron.

```c++
HANDLE CreateTimerQueue ();

BOOL CreateTimerQueueTimer(PHANDLE phNewTimer, HANDLE TimerQueue, WAITORTIMERCALLBACK Callback, PVOID Parameter, DWORD DueTime, DWORD Period, ULONG Flags);

HANDLE CreateEventA(LPSECURITY_ATTRIBUTES lpEventAttributes, BOOL bManualReset, BOOL bInitialState, LPCSTR lpName);

DWORD WaitForSingleObject (HANDLE hHandle, DWORD dwMilliseconds);
```

### Reference 

- [MSDN CreateTimerQueue](https://docs.microsoft.com/en-us/windows/win32/api/threadpoollegacyapiset/nf-threadpoollegacyapiset-createtimerqueue)
- [MSDN CreateTimerQueueTimer](https://docs.microsoft.com/en-us/windows/win32/api/threadpoollegacyapiset/nf-threadpoollegacyapiset-createtimerqueuetimer)
- [MSDN CreateEventA](https://docs.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-createeventa)
- [MSDN WaitForSingleObject](https://docs.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject)