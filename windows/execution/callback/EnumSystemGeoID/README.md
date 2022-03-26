# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `EnumSystemGeoID`.

```c++
BOOL EnumSystemGeoID (GEOCLASS GeoClass,GEOID ParentGeoId,GEO_ENUMPROC lpGeoEnumProc;
```

### Reference 

- [MSDN EnumSystemGeoID](https://docs.microsoft.com/en-us/windows/win32/api/winnls/nf-winnls-enumsystemgeoid)