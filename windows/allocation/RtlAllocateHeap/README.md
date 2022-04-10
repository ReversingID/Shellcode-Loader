# Shellcode Loader

Allocate memory for executing shellcode later.

### Overview

Alokasi menggunakan `RtlAllocateHeap`. Namun, alokasi dilakukan pada segment heap terpisah dan tidak menggunakan Heap default.

```c++
PVOID RtlAllocateHeap (PVOID HeapHandle, ULONG Flags, SIZE_T Size);

PVOID RtlCreateHeap (ULONG Flags, PVOID HeapBase, SIZE_T ReserveSize, SIZE_T CommitSize, PVOID Lock, PRTL_HEAP_PARAMETERS Parameters);

LOGICAL RtlFreeHeap (PVOID HeapHandle, ULONG Flags, PVOID BaseAddress);

PVOID RtlDestroyHeap (PVOID HeapHandle);
```

### Reference 

- [MSDN RtlAllocateHeap](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlallocateheap)
- [MSDN RtlCreateHeap](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlcreateheap)
- [MSDN RtlFreeHeap](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlfreeheap)
- [MSDN RtlDestroyheap](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtldestroyheap)