# Shellcode Loader

Executing shellcode as a fiber.

### Overview

Eksekusi shellcode dengan `CreateFiberEx`.

```c++
LPVOID CreateFiberEx (SIZE_T dwStackCommitSize, SIZE_T dwStackReserveSize, LPFIBER_START_ROUTINE lpStartAddress, LPVOID lpParameter);

LPVOID ConvertThreadToFiber(LPVOID lpParameter);
```

### Reference 

- [MSDN CreateFiberEx](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createfiberex)
- [MSDN ConvertThreadToFiber](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-convertthreadtofiber)