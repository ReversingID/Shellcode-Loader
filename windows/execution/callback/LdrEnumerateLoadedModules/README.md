# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `LdrEnumerateLoadedModules`.

`LdrEnumerateLoadedModules` adalah fungsi internal dan bersifat low-level

```c++
NTSTATUS LdrEnumerateLoadedModules (BOOL ReservedFlag, LDR_ENUM_CALLBACK EnumProc, PVOID context);
```

### Reference 

