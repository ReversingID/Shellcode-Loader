# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `SHBrowseForFolder`.

```c++
PIDLIST_ABSOLUTE SHBrowseForFolderA (LPBROWSEINFOA lpbi);

PIDLIST_ABSOLUTE SHBrowseForFolderW (LPBROWSEINFOA lpbi);
```

### Reference 

- [MSDN SHBrowseForFolderA](https://docs.microsoft.com/en-us/windows/win32/api/shlobj_core/nf-shlobj_core-shbrowseforfoldera)
- [MSDN SHBrowseForFolderW](https://docs.microsoft.com/en-us/windows/win32/api/shlobj_core/nf-shlobj_core-shbrowseforfolderw)