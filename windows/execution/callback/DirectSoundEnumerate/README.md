# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `DirectSoundEnumerate`.

```c++
HRESULT DirectSoundEnumerate (LPDSENUMCALLBACK lpDSEnumCallback, LPVOID lpContext);
```

### Reference 

- [MSDN DirectSoundEnumerate](https://docs.microsoft.com/en-us/previous-versions/windows/desktop/ee416763(v=vs.85))