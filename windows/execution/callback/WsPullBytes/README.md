# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `WsPullBytes`.

```c++
HRESULT WsPullBytes (WS_XML_WRITER *writer, WS_PULL_BYTES_CALLBACK callback, void *callbackState, WS_ERROR *error);

HRESULT WsCreateWriter (const WS_XML_WRITER_PROPERTY *properties, ULONG propertyCount, WS_XML_WRITER **writer, WS_ERROR *error);

HRESULT WsSetOutput (WS_XML_WRITER *writer, const WS_XML_WRITER_ENCODING *encoding, const WS_XML_WRITER_OUTPUT *output, const WS_XML_WRITER_PROPERTY *properties, ULONG propertyCount, WS_ERROR *error);
```

### Reference 

- [MSDN WsPullBytes](https://docs.microsoft.com/en-us/windows/win32/api/webservices/nf-webservices-wspullbytes)
- [MSDN WsCreateWriter](https://docs.microsoft.com/en-us/windows/win32/api/webservices/nf-webservices-wscreatewriter)
- [MSDN WsSetOutput](https://docs.microsoft.com/en-us/windows/win32/api/webservices/nf-webservices-wssetoutput)