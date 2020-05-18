.CODE 

MyOpenProcess PROC
	int 3
	mov r12, rsp
	sub rsp, 100h

	lea rax, dword ptr [r12 - 8h]
	xchg rax, rcx
	mov [rcx] ,rax				; arg 1

	mov rdx, 10000000h	;arg 2
	xor r8, r8						;arg 3
	mov eax, 26h
	lea r9, [r12 - 10h]			;arg 4
	mov qword ptr [r9], 0

	mov r10, rcx
	syscall 

	add rsp, 100h
	mov rax,[r12 - 10h]

	ret
MyOpenProcess  ENDP

MyTerminateProcess PROC
	mov rsi, rsp
	sub rsp, 100h

	push 0
	push [rsi + 8h]

	mov eax, 2ch
	syscall 

	add rsp, 10h
	add rsp,100h
	ret

MyTerminateProcess ENDP

END