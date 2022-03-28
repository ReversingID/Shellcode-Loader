# Shellcode Loader

Writing shellcode to allocated memory.

### Overview

Penyalinan shellcode menggunakan `Decompress`.

```c++
BOOL Decompress (DECOMPRESSOR_HANDLE DecompressorHandle, LPCVOID CompressedData, SIZE_T CompressedDataSize, PVOID UncompressedBuffer, SIZE_T UncompressedBufferSize, PSIZE_T UncompressedDataSize);

BOOL CreateDecompressor (DWORD Algorithm, PCOMPRESS_ALLOCATION_ROUTINES AllocationRoutines, PDECOMPRESSOR_HANDLE DecompressorHandle);

BOOL Compress (COMPRESSOR_HANDLE CompressorHandle, LPCVOID UncompressedData, SIZE_T UncompressedDataSize, PVOID CompressedBuffer, SIZE_T CompressedBufferSize, PSIZE_T CompressedDataSize);

BOOL CreateCompressor (DWORD Algorithm, PCOMPRESS_ALLOCATION_ROUTINES AllocationRoutines, PCOMPRESSOR_HANDLE CompressorHandle);
```

### Reference

- [MSDN Decompress](https://docs.microsoft.com/en-us/windows/win32/api/compressapi/nf-compressapi-decompress)
- [MSDN Compress](https://docs.microsoft.com/en-us/windows/win32/api/compressapi/nf-compressapi-compress)
- [MSDN CreateDecompressor](https://docs.microsoft.com/en-us/windows/win32/api/compressapi/nf-compressapi-createdecompressor)
- [MSDN CreateCompressor](https://docs.microsoft.com/en-us/windows/win32/api/compressapi/nf-compressapi-createcompressor)