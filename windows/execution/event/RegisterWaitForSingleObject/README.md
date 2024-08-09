# Shellcode Loader

Executing shellcode using timer.

### Overview

Eksekusi shellcode dengan `RegisterWaitForSingleObject`.

```c++
BOOL RegisterWaitForSingleObject(PHANDLE phNewWaitObject, HANDLE hObject, WAITORTIMERCALLBACK Callback, PVOID Context, ULONG dwMilliseconds, ULONG dwFlags);

HANDLE CreateEventA(LPSECURITY_ATTRIBUTES lpEventAttributes, BOOL bManualReset, BOOL bInitialState, LPCSTR lpName);

BOOL UnregisterWait(HANDLE WaitHandle);
```

### Reference 

- [MSDN RegisterWaitForSingleObject](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-registerwaitforsingleobject)
- [MSDN CreateEventA](https://docs.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-createeventa)
- [MSDN UnregisterWait](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-unregisterwait)