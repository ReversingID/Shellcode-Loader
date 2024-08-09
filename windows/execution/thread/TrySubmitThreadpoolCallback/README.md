# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `TrySubmitThreadpoolCallback`.

```c++
BOOL TrySubmitThreadpoolCallback(PTP_SIMPLE_CALLBACK pfns, PVOID pv,PTP_CALLBACK_ENVIRON pcbe);
```

### Reference 

- [MSDN TrySubmitThreadpoolCallback](https://learn.microsoft.com/en-us/windows/win32/api/threadpoolapiset/nf-threadpoolapiset-trysubmitthreadpoolcallback)