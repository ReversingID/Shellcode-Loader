# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `DSA_DestroyCallback`.

```c++
void DSA_DestroyCallback (HDSA hdsa, PFNDAENUMCALLBACK pfnCB, void *pData);

HDSA DSA_Create (int cbItem, int cItemGrow);

int DSA_InsertItem (HDSA hdsa, int i, const void *pitem);
```

### Reference 

- [MSDN DSA_DestroyCallback](https://docs.microsoft.com/en-us/windows/win32/api/dpa_dsa/nf-dpa_dsa-dsa_destroycallback)
- [MSDN DSA_Create](https://docs.microsoft.com/en-us/windows/win32/api/dpa_dsa/nf-dpa_dsa-dsa_create)
- [MSDN DSA_InsertItem](https://docs.microsoft.com/en-us/windows/win32/api/dpa_dsa/nf-dpa_dsa-dsa_insertitem)