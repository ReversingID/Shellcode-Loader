# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `SetupCommitFileQueue`.

```c++
WINSETUPAPI BOOL SetupCommitFileQueueA (HWND Owner, HSPFILEQ QueueHandle, PSP_FILE_CALLBACK_A MsgHandler, PVOID Context);

WINSETUPAPI BOOL SetupCommitFileQueueW (HWND Owner, HSPFILEQ QueueHandle, PSP_FILE_CALLBACK_W MsgHandler, PVOID Context);

WINSETUPAPI BOOL SetupQueueCopyA (HSPFILEQ QueueHandle, PCSTR SourceRootPath, PCSTR SourcePath, PCSTR SourceFilename, PCSTR SourceDescription, PCSTR SourceTagfile, PCSTR TargetDirectory, PCSTR TargetFilename, DWORD CopyStyle);

WINSETUPAPI BOOL SetupQueueCopyW (HSPFILEQ QueueHandle, PCWSTR SourceRootPath, PCWSTR SourcePath, PCWSTR SourceFilename, PCWSTR SourceDescription, PCWSTR SourceTagfile, PCWSTR TargetDirectory, PCWSTR TargetFilename, DWORD CopyStyle);

WINSETUPAPI HSPFILEQ SetupOpenFileQueue();
```

### Reference 

- [MSDN SetupCommitFileQueueA](https://docs.microsoft.com/en-us/windows/win32/api/setupapi/nf-setupapi-setupcommitfilequeuew)
- [MSDN SetupCommitFileQueueW](https://docs.microsoft.com/en-us/windows/win32/api/setupapi/nf-setupapi-setupcommitfilequeuew)
- [MSDN SetupQueueCopyA](https://docs.microsoft.com/en-us/windows/win32/api/setupapi/nf-setupapi-setupqueuecopya)
- [MSDN SetupQueueCopyW](https://docs.microsoft.com/en-us/windows/win32/api/setupapi/nf-setupapi-setupqueuecopyw)
- [MSDN SetupOpenFileQueue](https://docs.microsoft.com/en-us/windows/win32/api/setupapi/nf-setupapi-setupopenfilequeue)