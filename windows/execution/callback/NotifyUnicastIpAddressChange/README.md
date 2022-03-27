# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `NotifyUnicastIpAddressChange`.

```c++
IPHLPAPI_DLL_LINKAGE _NETIOAPI_SUCCESS_ NETIOAPI_API 
NotifyUnicastIpAddressChange (ADDRESS_FAMILY Family, PUNICAST_IPADDRESS_CHANGE_CALLBACK Callback, PVOID CallerContext, BOOLEAN InitialNotification, HANDLE *NotificationHandle);
```

### Reference 

- [MSDN NotifyUnicastIpAddressChange](https://docs.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-notifyunicastipaddresschange)