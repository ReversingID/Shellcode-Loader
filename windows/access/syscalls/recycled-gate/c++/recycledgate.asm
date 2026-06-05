; Recycled Gate — static trampoline into ntdll's syscall;ret (x64)
; SSN and recycled syscall address in .data; RecycledDescent in .text (no heap allocation)

.data
    wSystemCall      DWORD 0
    pRecycledSyscall QWORD 0

.code
RecycledGate PROC
    mov wSystemCall, ecx
    ret
RecycledGate ENDP

RecycledSetSyscallAddr PROC
    mov pRecycledSyscall, rcx
    ret
RecycledSetSyscallAddr ENDP

RecycledDescent PROC
    mov r10, rcx
    mov eax, wSystemCall
    mov r11, QWORD PTR pRecycledSyscall
    jmp r11
RecycledDescent ENDP
END
