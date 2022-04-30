# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `mmioInstallIOProc`.

```c++
LPMMIOPROC mmioInstallIOProc (FOURCC fccIOProc, LPMMIOPROC pIOProc, DWORD dwFlags);

MCIERROR mciSendString (LPCTSTR lpszCommand, LPTSTR lpszReturnString, UINT cchReturn, HANDLE hwndCallback);
```

### Reference 

- [MSDN mmioInstallIOProc](https://docs.microsoft.com/en-us/windows/win32/api/mmiscapi/nf-mmiscapi-mmioinstallioproc)
- [MSDN mciSendString](https://docs.microsoft.com/en-us/previous-versions//dd757161(v=vs.85))