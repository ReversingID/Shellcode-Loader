# Shellcode Loader

Allocate memory for executing shellcode later.

### Overview

Alokasi menggunakan `CoTaskMemAlloc`.

```c++
LPVOID CoTaskMemAlloc (SIZE_T cb);

void CoTaskMemFree (LPVOID pv);
```

### Reference 

- [MSDN CoTaskMemAlloc](https://docs.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-cotaskmemalloc)
- [MSDN CoTaskMemFree](https://docs.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-cotaskmemfree)