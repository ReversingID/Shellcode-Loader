# Shellcode Loader

Writing shellcode to allocated memory.

### Overview

Penyalinan shellcode menggunakan `MoveMemory`.

```c++
void MoveMemory (PVOID Destination, const VOID *Source, SIZE_T Length);
```

### Reference

- [MSDN MoveMemory](https://docs.microsoft.com/en-us/previous-versions/windows/desktop/legacy/aa366788(v=vs.85))