# Shellcode Loader

Executing shellcode using timer.

### Overview

Eksekusi shellcode dengan `CreateWaitableTimer` dan `SetWaitableTimer`.

Waitable timer adalah objek synchronization yang akan memberikan signal ketika tenggat waktu terpenuhi dan mengeksekusi sebuah callback. 

Callback merupakan sebuah APC (Asynchronous Procedure Call) dan dieksekusi oleh thread yang memanggil `SetWaitableTimer`. Thread haruslah dalam kondisi alertable untuk dapat memanggil callback, salah satunya dapat menggunakan `SleepEx`.

```c++
HANDLE CreateWaitableTimerW(LPSECURITY_ATTRIBUTES lpTimerAttributes, BOOL bManualReset, LPCWSTR lpTimerName);

BOOL SetWaitableTimer(HANDLE hTimer, const LARGE_INTEGER *lpDueTime, LONG lPeriod, PTIMERAPCROUTINE pfnCompletionRoutine, LPVOID lpArgToCompletionRoutine, BOOL fResume);

DWORD SleepEx(DWORD dwMilliseconds, BOOL bAlertable);

DWORD WaitForSingleObject (HANDLE hHandle, DWORD dwMilliseconds);
```

### Reference 

- [MSDN CreateWaitableTimer](https://docs.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-createwaitabletimerw)
- [MSDN SetWaitableTimer](https://docs.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-setwaitabletimer)
- [MSDN SleepEx](https://docs.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-sleepex)
- [MSDN WaitForSingleObject](https://docs.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject)