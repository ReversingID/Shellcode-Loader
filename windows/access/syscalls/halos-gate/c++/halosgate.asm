; Halo's Gate — static syscall trampoline (x64)
; SSN in .data; HaloDescent in .text (no heap allocation)

.data
    wSystemCall DWORD 0

.code
HalosGate PROC
    mov wSystemCall, ecx
    ret
HalosGate ENDP

HaloDescent PROC
    mov r10, rcx
    mov eax, wSystemCall
    syscall
    ret
HaloDescent ENDP
END
