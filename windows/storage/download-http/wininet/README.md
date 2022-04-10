# Shellcode Loader

Download shellcode over HTTP protocol.

### Overview

Shellcode disimpan sebagai array of byte dan disediakan melalui HTTP.

Menggunakan WinInet API untuk melakukan operasi HTTP.

```c++
HINTERNET InternetOpenA (LPCSTR lpszAgent, DWORD dwAccessType, LPCSTR lpszProxy, LPCSTR lpszProxyBypass, DWORD dwFlags);

HINTERNET InternetOpenW (LPCWSTR lpszAgent, DWORD dwAccessType, LPCWSTR lpszProxy, LPCWSTR lpszProxyBypass, DWORD dwFlags);

HINTERNET InternetConnectA (HINTERNET hInternet, LPCSTR lpszServerName, INTERNET_PORT nServerPort, LPCSTR lpszUserName, LPCSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext);

HINTERNET InternetConnectw (HINTERNET hInternet, LPCWSTR lpszServerName, INTERNET_PORT nServerPort, LPCWSTR lpszUserName, LPCWSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext);

HINTERNET HttpOpenRequestA (HINTERNET hConnect, LPCSTR lpszVerb, LPCSTR lpszObjectName, LPCSTR lpszVersion, LPCSTR lpszReferrer, LPCSTR lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext);

HINTERNET HttpOpenRequestW (HINTERNET hConnect, LPCWSTR lpszVerb, LPCWSTR lpszObjectName, LPCWSTR lpszVersion, LPCWSTR lpszReferrer, LPCWSTR lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext);

BOOL HttpSendRequestA (HINTERNET hRequest, LPCSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength);

BOOL HttpSendRequestW (HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength);

BOOL InternetReadFile (HINTERNET hFile, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead);
```

### Reference 

- [MSDN InternetOpenA](https://docs.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetopena)
- [MSDN InternetOpenW](https://docs.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetopenw)
- [MSDN InternetConnectA](https://docs.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetconnecta)
- [MSDN InternetConnectW](https://docs.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetconnectw)
- [MSDN WinHttpCloseHandle](https://docs.microsoft.com/en-us/windows/win32/api/winhttp/nf-winhttp-winhttpclosehandle)
- [MSDN HttpOpenRequestA](https://docs.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-httpopenrequesta)
- [MSDN HttpOpenRequestW](https://docs.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-httpopenrequestw)
- [MSDN HttpSendRequestA](https://docs.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-httpsendrequesta)
- [MSDN HttpSendRequestW](https://docs.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-httpsendrequestw)
- [MSDN InternetReadFile](https://docs.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetreadfile)