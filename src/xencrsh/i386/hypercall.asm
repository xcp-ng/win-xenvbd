                page    ,132
                title   Hypercall Gates

                .686p
                .model  FLAT
                .code

                extrn   _Hypercall:dword

                ; uintptr_t __stdcall asm___hypercall2(uint32_t ord, uintptr_t arg1, uintptr_t arg2);
                public _asm___hypercall2@12
_asm___hypercall2@12 proc
                push    ebp
                mov     ebp, esp
                push    ebx
                mov     eax, [ebp + 08h]                ; ord
                mov     ebx, [ebp + 0ch]                ; arg1
                mov     ecx, [ebp + 10h]                ; arg2
                shl     eax, 5
                add     eax, dword ptr [_Hypercall]
                call    eax
                pop     ebx
                leave
                ret     0Ch
_asm___hypercall2@12 endp

                ; uintptr_t __stdcall asm___hypercall3(uint32_t ord, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3);
                public _asm___hypercall3@16
_asm___hypercall3@16 proc
                push    ebp
                mov     ebp, esp
                push    ebx
                mov     eax, [ebp + 08h]                ; ord
                mov     ebx, [ebp + 0ch]                ; arg1
                mov     ecx, [ebp + 10h]                ; arg2
                mov     edx, [ebp + 14h]                ; arg3
                shl     eax, 5
                add     eax, dword ptr [_Hypercall]
                call    eax
                pop     ebx
                leave
                ret     10h
_asm___hypercall3@16 endp

                end
