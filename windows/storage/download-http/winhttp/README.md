# Shellcode Loader

Download shellcode over HTTP protocol.

### Overview

Shellcode disimpan sebagai array of byte dan disediakan melalui HTTP.

Menggunakan WinHTTP API untuk melakukan operasi HTTP.

```c++
HINTERNET WinHttpOpen (LPCWSTR pszAgentW, DWORD dwAccessType, LPCWSTR pszProxyW, LPCWSTR pszProxyBypassW, DWORD dwFlags);

HINTERNET WinHttpConnect (HINTERNET hSession, LPCWSTR pswzServerName, INTERNET_PORT nServerPort, DWORD dwReserved);

HINTERNET WinHttpOpenRequest (HINTERNET hConnect, LPCWSTR pwszVerb, LPCWSTR pwszObjectName, LPCWSTR pwszVersion, LPCWSTR pwszReferrer, LPCWSTR *ppwszAcceptTypes, DWORD dwFlags);

BOOL WinHttpSendRequest (HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength, DWORD dwTotalLength, DWORD_PTR dwContext);

BOOL WinHttpReceiveResponse (HINTERNET hRequest, LPVOID lpReserved);

BOOL WinHttpReadData (HINTERNET hRequest, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead);

BOOL WinHttpCloseHandle (HINTERNET hInternet);
```

### Reference 

- [MSDN WinHttpOpen](https://docs.microsoft.com/en-us/windows/win32/api/winhttp/nf-winhttp-winhttpopen)
- [MSDN WinHttpConnect](https://docs.microsoft.com/en-us/windows/win32/api/winhttp/nf-winhttp-winhttpconnect)
- [MSDN WinHttpOpenRequest](https://docs.microsoft.com/en-us/windows/win32/api/winhttp/nf-winhttp-winhttpopenrequest)
- [MSDN WinHttpSendRequest](https://docs.microsoft.com/en-us/windows/win32/api/winhttp/nf-winhttp-winhttpsendrequest)
- [MSDN WinHttpReceiveResponse](https://docs.microsoft.com/en-us/windows/win32/api/winhttp/nf-winhttp-winhttpreceiveresponse)
- [MSDN WinHttpReadData](https://docs.microsoft.com/en-us/windows/win32/api/winhttp/nf-winhttp-winhttpreaddata)
- [MSDN WinHttpCloseHandle](https://docs.microsoft.com/en-us/windows/win32/api/winhttp/nf-winhttp-winhttpclosehandle)