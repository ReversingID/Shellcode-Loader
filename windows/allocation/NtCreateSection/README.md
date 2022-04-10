# Shellcode Loader

Allocate memory for executing shellcode later.

### Overview

Alokasi menggunakan beberapa fungsi internal:
- `NtCreateSection`
- `NtMapViewOfSection`

Teknik ini akan membuat sebuah section baru saat runtime yang dapat menampung shellcode. Section haruslah executable saat eksekusi dan telah dipetakan ke process.

```c++
NTSTATUS NtCreateSection (PHANDLE SectionHandle, ULONG DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize, ULONG PageAttributess, ULONG SectionAttributes, HANDLE FileHandle);

NTSTATUS NtMapViewOfSection (HANDLE SectionHandle, HANDLE ProcessHandle, PVOID *BaseAddress, ULONG ZeroBits, ULONG CommitSize, PLARGE_INTEGER SectionOffset, PULONG ViewSize, DWORD InheritDisposition, ULONG AllocationType, ULONG Protect);

NTSTATUS NtUnmapViewOfSection (HANDLE ProcessHandle, PVOID BaseAddress);

NTSTATUS NtClose (HANDLEObjectHandle);
```

### Reference 

- [NTInternals NtCreateSection](http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FSection%2FNtCreateSection.html)
- [NtInternals NtMapViewOfSection](http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Section/NtMapViewOfSection.html)
- [NtInternals NtUnmapViewOfSection](http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Section/NtUnmapViewOfSection.html)
- [NtInternals NtClose](http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FType%20independed%2FNtClose.html)