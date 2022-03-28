# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `NotifyTeredoPortChange`.

```c++
IPHLPAPI_DLL_LINKAGE _NETIOAPI_SUCCESS_ NETIOAPI_API
NotifyTeredoPortChange ( PTEREDO_PORT_CHANGE_CALLBACK Callback, PVOID CallerContext, BOOLEAN InitialNotification, HANDLE *NotificationHandle);
```

### Reference 

- [MSDN NotifyTeredoPortChange](https://docs.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-notifyteredoportchange)