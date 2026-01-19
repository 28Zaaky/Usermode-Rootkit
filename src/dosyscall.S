# ============================================================================
# DoSyscall - Indirect Syscall Stub for GCC/MinGW (x64)
# ============================================================================
# Windows x64 calling convention:
#   RCX = ssn, RDX = syscallAddr, R8 = arg1, R9 = arg2
#   Stack: arg3, arg4, arg5, arg6
#
# Syscall expects:
#   EAX = SSN, R10 = arg1, RDX = arg2, R8 = arg3, R9 = arg4
#   Stack: arg5, arg6
# ============================================================================

.text
.globl DoSyscall
.def DoSyscall; .scl 2; .type 32; .endef

DoSyscall:
    # Save non-volatile registers
    pushq %rbx
    pushq %rsi
    
    # Save syscallAddr and SSN
    movq %rdx, %rbx             # RBX = syscallAddr
    movl %ecx, %esi             # ESI = SSN (32-bit is enough)
    
    # Load arguments BEFORE modifying stack
    # R10 = arg1, RDX = arg2, R8 = arg3, R9 = arg4
    movq %r8, %r10              # R10 = arg1
    movq %r9, %rdx              # RDX = arg2
    movq 0x38(%rsp), %r8        # R8  = arg3 (0x28 + 0x10 for 2 pushes)
    movq 0x40(%rsp), %r9        # R9  = arg4
    
    # Setup stack for CALL
    # We need arg5 and arg6 at correct positions
    # Currently: arg5 at [RSP+0x48], arg6 at [RSP+0x50] (because of 2 pushes)
    # After sub and call: arg5 must be at [RSP+0x28], arg6 at [RSP+0x30]
    
    subq $0x38, %rsp            # Allocate 56 bytes (shadow 32 + 24 for args)
    
    # Copy arg5 and arg6
    movq 0x80(%rsp), %rax       # arg5 original (0x48+0x38=0x80)
    movq %rax, 0x20(%rsp)       # arg5 at RSP+0x20 → RSP+0x28 after CALL
    
    movq 0x88(%rsp), %rax       # arg6 original (0x50+0x38=0x88)
    movq %rax, 0x28(%rsp)       # arg6 at RSP+0x28 → RSP+0x30 after CALL
    
    # Set SSN
    movl %esi, %eax
    
    # CALL syscall gadget
    call *%rbx
    
    # Cleanup
    addq $0x38, %rsp
    popq %rsi
    popq %rbx
    ret
