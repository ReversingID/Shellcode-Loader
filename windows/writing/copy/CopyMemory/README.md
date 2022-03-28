# Shellcode Loader

Writing shellcode to allocated memory.

### Overview

Penyalinan shellcode menggunakan `CopyMemory`.

```c++
void CopyMemory (PVOID Destination, const VOID *Source, SIZE_T Length);
```

### Reference

- [MSDN CopyMemory](https://docs.microsoft.com/en-us/previous-versions/windows/desktop/legacy/aa366535(v=vs.85))