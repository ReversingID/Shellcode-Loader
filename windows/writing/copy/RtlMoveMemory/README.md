# Shellcode Loader

Writing shellcode to allocated memory.

### Overview

Penyalinan shellcode menggunakan `RtlMoveMemory`.

```c++
VOID RtlMoveMemory (VOID *Destination, const VOID *Source, SIZE_T Length);
```

### Reference

- [MSDN RtlMoveMemory](https://docs.microsoft.com/en-us/windows/win32/devnotes/rtlmovememory)