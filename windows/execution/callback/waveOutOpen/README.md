# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `waveOutOpen`.

```c++
MMRESULT waveOutOpen(LPHWAVEOUT phwo, UINT uDeviceID, LPCWAVEFORMATEX pwfx, DWORD_PTR dwCallback, DWORD_PTR dwInstance, DWORD fdwOpen);
```

### Reference 

- [MSDN waveOutOpen](https://learn.microsoft.com/en-us/windows/win32/api/mmeapi/nf-mmeapi-waveoutopen)
- [MSDN structure WAVEFORMATEX](https://learn.microsoft.com/en-us/previous-versions/dd757713(v=vs.85))