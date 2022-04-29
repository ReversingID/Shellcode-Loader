# Shellcode Loader

Executing shellcode using timer.

### Overview

Eksekusi shellcode dengan `timeSetEvent`.

Fungsi ini tergolong obsolete.

```c++
MMRESULT timeSetEvent (UINT uDelay, UINT uResolution, LPTIMECALLBACK lpTimeProc, DWORD_PTR dwUser, UINT fuEvent);

MMRESULT timeKillEvent (uTimerID);

MMRESULT timeBeginPeriod (UINT uPeriod);

MMRESULT timeGetDevCaps (LPTIMECAPS ptc, UINT cbtc);
```

### Reference 

- [MSDN timeSetEvent](https://docs.microsoft.com/en-us/previous-versions//dd757634(v=vs.85))
- [MSDN timeKillEvent](https://docs.microsoft.com/en-us/previous-versions//dd757630(v=vs.85))
- [MSDN timeGetDevCaps](https://docs.microsoft.com/en-us/windows/win32/api/timeapi/nf-timeapi-timegetdevcaps)
- [MSDN timeBeginPeriod](https://docs.microsoft.com/en-us/windows/win32/api/timeapi/nf-timeapi-timebeginperiod)