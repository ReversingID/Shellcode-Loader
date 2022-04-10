# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `LdrpCallInitRoutine`.

`LdrpCallInitRoutine` adalah fungsi internal dan bersifat low-level

```c++
char LdrpCallInitRoutine (LpCallInitRoutine callback, size_t, unsigned int, size_t)
```

### Reference 

