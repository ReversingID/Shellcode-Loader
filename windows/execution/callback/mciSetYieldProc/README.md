# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `mciSetYieldProc`.

Shellcode akan dipanggil secara berkala (periodik) ketika MCI device menerima flag MCI_WAIT.

```c++
UINT mciSetYieldProc (MCIDEVICEID IDDevice, YIELDPROC yp, DWORD dwYieldData);

MCIERROR mciSendCommand (MCIDEVICEID IDDevice, UINT uMsg, DWORD_PTR fdwCommand, DWORD_PTR dwParam);
```

### Reference 

- [MSDN mciSetYieldProc](https://docs.microsoft.com/en-us/previous-versions/dd757163(v=vs.85))
- [MSDN mciSendCommand](https://docs.microsoft.com/en-us/previous-versions//dd757160(v=vs.85))