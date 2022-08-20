# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `DPA_EnumCallback`.

```c++
void DPA_DestroyCallback (HDPA hdpa, PFNDAENUMCALLBACK pfnCB, void *pData);

HDPA DPA_Create (int cItemGrow);

int DPA_InsertPtr (HDPA hdpa, int i, void *p);
```

### Reference 

- [MSDN DPA_DestroyCallback](https://docs.microsoft.com/en-us/windows/win32/api/dpa_dsa/nf-dpa_dsa-dpa_destroycallback)
- [MSDN DPA_Create](https://docs.microsoft.com/en-us/windows/win32/api/dpa_dsa/nf-dpa_dsa-dpa_create)
- [MSDN DPA_InsertPtr](https://docs.microsoft.com/en-us/windows/win32/api/dpa_dsa/nf-dpa_dsa-dpa_insertptr)