# Shellcode Loader

Executing shellcode as a thread.

### Overview

Eksekusi shellcode dengan `RtlUserFiberStart`.

`RtlUserFiberStart` adalah fungsi internal dan bersifat low-level.

```c++
NTSTATUS RtluserFiberStart();
```

### Reference 

- [MSDN TEB (Thread Environment Block)](https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-teb)
    - [TEB](https://processhacker.sourceforge.io/doc/struct___t_e_b.html)
    - [TEB32](https://processhacker.sourceforge.io/doc/struct___t_e_b32.html)
- [Wiki Thread Information Block](https://en.wikipedia.org/wiki/Win32_Thread_Information_Block)
    - [NT_TIB](https://kernelstruct.gitee.io/kernels/x64/Windows%2010%20|%202016/1803%20Redstone%204%20(Spring%20Creators%20Update)/_NT_TIB)
    - [NT_TIB32](https://kernelstruct.gitee.io/kernels/x64/Windows%2010%20%7C%202016/1803%20Redstone%204%20(Spring%20Creators%20Update)/_NT_TIB32)
- [MSDN NtCurrentTeb](https://docs.microsoft.com/en-us/windows/win32/api/winnt/nf-winnt-ntcurrentteb)