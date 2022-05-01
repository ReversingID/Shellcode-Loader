# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `PlaExtractCabinet`.

```c++
HRESULT PlaExtractCabinet (PCWSTR CabFileName, PCWSTR DestPath, PLA_CABEXTRACT_CALLBACK Callback, PVOID Context);
```

### Reference 

- [github pla.h](https://github.com/nihon-tc/Rtest/blob/master/header/Microsoft%20SDKs/Windows/v7.0A/Include/pla.h)