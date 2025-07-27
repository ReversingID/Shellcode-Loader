# Shellcode Loader

### Overview

Teknik `allocation` digunakan untuk menciptakan ruang yang cukup untuk menampung shellcode yang telah diekstrak dari ruang penyimpanan (global/stack/resource/download). Memory yang telah dialokasikan haruslah ditandai sebagai executable. Hal ini dilakukan untuk menghindari adanya exception oleh DEP (Data Execution Prevention).

### Catalog

Daftar teknik `allocation` yang diimplementasikan:

- [AllocADsMem](AllocADsMem)
- [CoTaskMemAlloc](CoTaskMemAlloc)
- [CreateFileMapping](CreateFileMapping)
- [GlobalAlloc-GHND](GlobalAlloc-GHND)
- [GlobalAlloc-GPTR](GlobalAlloc-GPTR)
- [HeapAlloc](HeapAlloc)
- [NtAllocateVirtualMemory](NtAllocateVirtualMemory)
- [NtCreateSection](NtCreateSection)
- [NtCreateSectionEx](NtCreateSectionEx)
- [RtlAllocateHeap](RtlAllocateHeap)
- [VirtualAlloc](VirtualAlloc)
- [VirtualAlloc2](VirtualAlloc2)
- [VirtualAllocEx](VirtualAllocEx)