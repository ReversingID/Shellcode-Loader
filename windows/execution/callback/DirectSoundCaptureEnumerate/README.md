# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `DirectSoundCaptureEnumerate`.

```c++
HRESULT DirectSoundCaptureEnumerate (LPDSENUMCALLBACK lpDSEnumCallback, LPVOID lpContext);
```

### Reference 

- [MSDN DirectSoundCaptureEnumerate](https://docs.microsoft.com/en-us/previous-versions/windows/desktop/ee416761(v=vs.85))