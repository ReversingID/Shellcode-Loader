# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `DPA_EnumCallback`.

```c++
void DPA_EnumCallback (HDPA hdpa, PFNDAENUMCALLBACK pfnCB, void *pData);

HDPA DPA_Create (int cItemGrow);

BOOL DPA_Destroy (HDPA hdpa);

int DPA_InsertPtr (HDPA hdpa, int i, void *p);
```

### Reference 

- [MSDN DPA_EnumCallback](https://docs.microsoft.com/en-us/windows/win32/api/dpa_dsa/nf-dpa_dsa-dpa_enumcallback)
- [MSDN DPA_Create](https://docs.microsoft.com/en-us/windows/win32/api/dpa_dsa/nf-dpa_dsa-dpa_create)
- [MSDN DPA_Destroy](https://docs.microsoft.com/en-us/windows/win32/api/dpa_dsa/nf-dpa_dsa-dpa_destroy)
- [MSDN DPA_InsertPtr](https://docs.microsoft.com/en-us/windows/win32/api/dpa_dsa/nf-dpa_dsa-dpa_insertptr)