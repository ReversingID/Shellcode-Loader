# Shellcode Loader

Allocate memory for executing shellcode later.

### Overview

Alokasi menggunakan `HeapAlloc`. Namun, alokasi dilakukan pada segment heap terpisah dan tidak menggunakan Heap default.

```c++
LPVOID HeapAlloc (HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);

HANDLE HeapCreate (DWORD flOptions, SIZE_T dwInitialSize, SIZE_T dwMaximumSize);

BOOL HeapFree (HANDLE hHeap, DWORD dwFlags, _Frees_ptr_opt_ LPVOID lpMem);

BOOL HeapDestroy (HANDLE hHeap);
```

### Reference 

- [MSDN HeapAlloc](https://docs.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapalloc)
- [MSDN HeapCreate](https://docs.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapcreate)
- [MSDN HeapFree](https://docs.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapfree)
- [MSDN HeapDestroy](https://docs.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapdestroy)