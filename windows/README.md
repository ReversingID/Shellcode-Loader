# Shellcode Loader

Beberapa API yang digunakan dalam proses loading shellcode.

## Memory Allocation

Digunakan untuk mengalokasikan area di memory untuk menampung shellcode.

```C
LPVOID  VirtualAlloc (LPVOID address, SIZE_T size, DWORD alloc_type, DWORD protection);

LPVOID  VirtualAllocEx (HANDLE proc, LPVOID address, SIZE_T size, DWORD alloc_type, DWORD protection);

HGLOBAL GlobalAlloc (UINT flags, SIZE_T length); 
```

## Memory Copy

Digunakan untuk menyalin data ke lokasi lain.

```C
VOID    RtlMoveMemory (VOID * destination, VOID * source, SIZE_T length);
```

## Permission

Digunakan untuk mengubah permission dari page atau area yang dialokasikan. Umumnya untuk memastikan bahwa memory menjadi executable.

```
BOOL    VirtualProtect (LPVOID address, SIZE_T size, DWORD new_protection, PDWORD old_protection);

BOOL    VirtualProtectEx (HANDLE proc, LPVOID address, SIZE_T size, DWORD new_protection, PDWORD old_protection)
```

## Execution

Digunakan untuk mengeksekusi shellcode sebagai thread terpisah.

```C
HANDLE  CreateThread (LPSECURITY_ATTRIBUTES attrs, SIZE_T stack_size, LPTHREAD_START_ROUTINE start_addr, LPVOID param, DWORD creation_flag, LPDWORD thread_id);

HANDLE  CreateRemoteThread (HANDLE proc, LPSECURITY_ATTRIBUTES attrs, SIZE_T stack_size, LPTHREAD_START_ROUTINE start_addr, LPVOID param, DWORD creation_flag, LPDWORD thread_id);

HANDLE  CreateRemoteThreadEx (HANDLE proc, LPSECURITY_ATTRIBUTES attrs, SIZE_T stack_size, LPTHREAD_START_ROUTINE start_addr, LPVOID param, DWORD creation_flag, LPPROC_THREAD_ATTRIBUTE_LIST attr_list, LPDWORD thread_id);
```