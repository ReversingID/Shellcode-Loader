# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `NotifyIpInterfaceChange`.

Fungsi ini tersedia untuk Windows Vista dan versi selanjutnya.

```c++
IPHLPAPI_DLL_LINKAGE _NETIOAPI_SUCCESS_ NETIOAPI_API 
NotifyIpInterfaceChange (ADDRESS_FAMILY Family, PIPINTERFACE_CHANGE_CALLBACK Callback, PVOID CallerContext, BOOLEAN InitialNotification, HANDLE *NotificationHandle);
```

### Reference 

- [MSDN NotifyIpInterfaceChange](https://docs.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-notifyipinterfacechange)