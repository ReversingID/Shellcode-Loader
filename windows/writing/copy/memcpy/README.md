# Shellcode Loader

Writing shellcode to allocated memory.

### Overview

Penyalinan shellcode menggunakan `memcpy`.

```c++
void * memcpy (void * destination, const void * source, size_t num);
```

### Reference

- [C++ memcpy](https://www.cplusplus.com/reference/cstring/memcpy/)