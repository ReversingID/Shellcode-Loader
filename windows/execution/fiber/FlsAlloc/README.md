# Shellcode Loader

Executing shellcode as a thread.

### Overview

Eksekusi shellcode dengan `FlsAlloc`.

`FlsAlloc` digunakan untuk mengalokasikan `FLS (Fiber Local Storage`) index dan dapat digunakan untuk menyimpan dan mengambil kembali data secara local terhadap Fiber.

```c++
DWORD FlsAlloc (PFLS_CALLBACK_FUNCTION lpCallback);

BOOL FlsSetValue (DWORD dwFlsIndex, PVOID lpFlsData);
```

### Reference 

- [MSDN FlsAlloc](https://docs.microsoft.com/fr-fr/windows/win32/api/fibersapi/nf-fibersapi-flsalloc)
- [MSDN FlsSetValue](https://docs.microsoft.com/en-us/windows/win32/api/fibersapi/nf-fibersapi-flssetvalue)