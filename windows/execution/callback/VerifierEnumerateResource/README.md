# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `VerifierEnumerateResource`.

```c++
ULONG VerifierEnumerateResource (HANDLE Process, ULONG Flags, ULONG ResourceType, AVRF_RESOURCE_ENUMERATE_CALLBACK ResourceCallback, PVOID EnumerationContext);
```

### Reference 

- [MSDN VerifierEnumerateResource](https://docs.microsoft.com/en-us/windows/win32/api/avrfsdk/nf-avrfsdk-verifierenumerateresource)