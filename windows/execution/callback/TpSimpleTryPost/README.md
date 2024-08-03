# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `TpSimpleTryPost`.

`TpSimpleTryPost` adalah fungsi internal dan bersifat low-level.

```c++
NTSTATUS TpSimpleTryPost(PTP_SIMPLE_CALLBACK callback, PVOID args, PTP_CALLBACK_ENVIRON environ);
```

### Reference 
