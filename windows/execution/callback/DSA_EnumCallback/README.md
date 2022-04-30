# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `DSA_EnumCallback`.

```c++
void DSA_EnumCallback (HDSA hdsa, PFNDAENUMCALLBACK pfnCB, void *pData);

HDSA DSA_Create (int cbItem, int cItemGrow);

BOOL DSA_Destroy (HDSA hdsa);

int DSA_InsertItem (HDSA hdsa, int i, const void *pitem);
```

### Reference 

- [MSDN DSA_EnumCallback](https://docs.microsoft.com/en-us/windows/win32/api/dpa_dsa/nf-dpa_dsa-dsa_enumcallback)
- [MSDN DSA_Create](https://docs.microsoft.com/en-us/windows/win32/api/dpa_dsa/nf-dpa_dsa-dsa_create)
- [MSDN DSA_Destroy](https://docs.microsoft.com/en-us/windows/win32/api/dpa_dsa/nf-dpa_dsa-dsa_destroy)
- [MSDN DSA_InsertItem](https://docs.microsoft.com/en-us/windows/win32/api/dpa_dsa/nf-dpa_dsa-dsa_insertitem)