# Shellcode Loader

Executing shellcode as a fiber.

### Overview

Eksekusi shellcode dengan `CreateFiber`.

```c++
LPVOID CreateFiber(SIZE_T dwStackSize, LPFIBER_START_ROUTINE lpStartAddress, LPVOID lpParameter);

LPVOID ConvertThreadToFiber(LPVOID lpParameter);
```

### Reference 

- [MSDN CreateFiber](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createfiber)
- [MSDN ConvertThreadToFiber](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-convertthreadtofiber)