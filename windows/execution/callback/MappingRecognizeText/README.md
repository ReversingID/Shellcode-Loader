# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `MappingRecognizeText`.

```c++
HRESULT MappingRecognizeText (PMAPPING_SERVICE_INFO pServiceInfo, LPCWSTR pszText, DWORD dwLength, DWORD dwIndex, PMAPPING_OPTIONS pOptions, PMAPPING_PROPERTY_BAG pbag);

HRESULT MappingGetServices (PMAPPING_ENUM_OPTIONS pOptions, PMAPPING_SERVICE_INFO *prgServices, DWORD *pdwServicesCount);

HRESULT MappingFreeServices (PMAPPING_SERVICE_INFO pServiceInfo);
```

### Reference 

- [MSDN MappingRecognizeText](https://docs.microsoft.com/en-us/windows/win32/api/elscore/nf-elscore-mappingrecognizetext)
- [MSDN MappingGetServices](https://docs.microsoft.com/en-us/windows/win32/api/elscore/nf-elscore-mappinggetservices)
- [MSDN MappingFreeServices](https://docs.microsoft.com/en-us/windows/win32/api/elscore/nf-elscore-mappingfreeservices)
- [MSDN structure MAPPING_OPTIONS](https://docs.microsoft.com/en-us/windows/win32/api/elscore/ns-elscore-mapping_options)