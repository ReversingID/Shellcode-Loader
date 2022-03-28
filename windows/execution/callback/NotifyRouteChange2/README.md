# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `NotifyRouteChange2`.

```c++
IPHLPAPI_DLL_LINKAGE _NETIOAPI_SUCCESS_ NETIOAPI_API 
NotifyRouteChange2 (ADDRESS_FAMILY AddressFamily, PIPFORWARD_CHANGE_CALLBACK Callback, PVOID CallerContext, BOOLEAN InitialNotification, HANDLE NotificationHandle);
```

### Reference 

- [MSDN NotifyRouteChange2](https://docs.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-notifyroutechange2)