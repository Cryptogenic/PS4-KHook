#include "hooking.h"

// kernel_initialize_dispatch writes the dispatch relay code and default hook entries into a code cave. This basically
// facilitates state tracking of hooks persistently across processes, that way no running daemon is needed - it's completely
// independent.
void kernel_initialize_dispatch(struct thread *td, void *argUnused)
{
    int i = 0;

    /*
     * Resolve symbols.
     */
    struct dispatch_table *dispatch   = (struct dispatch_table *)(KERNEL_DISPATCH_CODE_CAVE);
    void (*printf)(char *format, ...) = (void (*)(char *, ...))(KERNEL_PRINTF);

    // Backup cr0 to undo write protection enable later
    uint64_t cr0 = readCr0();

    /*
     * Write dispatch relay code into the code cave
     */
    printf("[PS4-KHook] Kernel base = %p\n", KERNEL_BASE);
    printf("[PS4-KHook] Writing dispatch relay code @ %p...\n", &dispatch->relayCode);

    // Disable write protection
    writeCr0(cr0 & ~X86_CR0_WP);

    // Load r10 with the current instruction pointer.
    //   lea r10, qword ptr [rip]  ; +0 = 4c 8d 15 00 00 00 00
    dispatch->relayCode[i++] = 0x4C;
    dispatch->relayCode[i++] = 0x8D;
    dispatch->relayCode[i++] = 0x15;
    dispatch->relayCode[i++] = 0x00;
    dispatch->relayCode[i++] = 0x00;
    dispatch->relayCode[i++] = 0x00;
    dispatch->relayCode[i++] = 0x00;

    // The previous instruction loads r10 with the RIP at the end of that instruction, so subtract 7 to account for the
    // offset.
    //   sub r10, 7 ; +0 = 49 83 ea 07
    dispatch->relayCode[i++] = 0x49;
    dispatch->relayCode[i++] = 0x83;
    dispatch->relayCode[i++] = 0xEA;
    dispatch->relayCode[i++] = 0x07;

    // The indexer needs to be multiplied by the entry size being 0x10, so shift left by 4.
    //   shl rax, 0x4 ; 48 c1 e0 04
    dispatch->relayCode[i++] = 0x48;
    dispatch->relayCode[i++] = 0xC1;
    dispatch->relayCode[i++] = 0xE0;
    dispatch->relayCode[i++] = 0x04;

    // The entries start after the dispatch relay code which is always +0x20 from the code cave
    //   add rax, 0x20 ; +0 = 48 83 c0 20
    dispatch->relayCode[i++] = 0x48;
    dispatch->relayCode[i++] = 0x83;
    dispatch->relayCode[i++] = 0xC0;
    dispatch->relayCode[i++] = 0x20;

    // Calculate the final location for the indexed hook entry.
    //   add rax, r10 ; +0 = 4c 01 d0
    dispatch->relayCode[i++] = 0x4C;
    dispatch->relayCode[i++] = 0x01;
    dispatch->relayCode[i++] = 0xD0;

    // Load the hook payload into rax.
    //   mov rax, qword ptr [rax] ; +0 = 48 8b 00
    dispatch->relayCode[i++] = 0x48;
    dispatch->relayCode[i++] = 0x8B;
    dispatch->relayCode[i++] = 0x00;

    // Jump to the hook.
    //   jmp rax ; +0 = ff e0
    dispatch->relayCode[i++] = 0xFF;
    dispatch->relayCode[i++] = 0xE0;

    // Re-enable write protection
    writeCr0(cr0);

    /*
     * Initialize the table with tagged values so we know right away if we tried to use an uninitialized hook entry.
     */
    printf("[PS4-KHook] Initializing dispatch table @ %p...\n", &dispatch->entries);

    // Disable write protection
    writeCr0(cr0 & ~X86_CR0_WP);

    for(int i = 0; i < (sizeof(dispatch->entries) / sizeof(struct hook_dispatch_entry)); i++)
    {
        // Tag value to crash on a known pointer on an uninitialized hook
        dispatch->entries[i].payloadAddress   = (void *)0x31313131;
        dispatch->entries[i].trampolineOffset = 0;
    }

    // Re-enable write protection
    writeCr0(cr0);
}

// kernel_install_hook reads the hook arguments setup at KEXEC_ARGS_BUFFER and installs a hook accordingly. This includes
// creating a trampoline, patching the hook into the target, and installing the hook into the dispatch table.
void kernel_install_hook(struct thread *td, void *argUnused)
{
    /*
     * Resolve symbols.
     */
    struct dispatch_table *dispatch     = (struct dispatch_table *)(KERNEL_DISPATCH_CODE_CAVE);
    void *map                           = (void *)(*(uint64_t *)(KERNEL_MAP));

    void (*printf)(char *format, ...)                           = (void (*)(char *, ...))(KERNEL_PRINTF);
    uint64_t* (*kmem_alloc)(void *map, uint64_t size)           = (uint64_t* (*)(void *, uint64_t))(KERNEL_KMEM_ALLOC);
    int (*copyin)(const void *uaddr, void *kaddr, size_t len)   = (int (*)(const void *, void *, size_t))(KERNEL_COPYIN);
    void (*memcpy)(void *to, const void *from, size_t n)        = (void (*)(void *, const void *, size_t))(KERNEL_MEMCPY);

    // Backup cr0 to undo write protection enable later
    uint64_t cr0 = readCr0();

    // Read arguments from the KEXEC_ARGS_BUFFER mapping
    struct install_hook_args args;
    copyin(KEXEC_ARGS_BUFFER, &args, sizeof(struct install_hook_args));

    // Resolve the target address by the user-provided offset to the kernel base
    void *targetAddr = (void *)(KERNEL_BASE + (uint64_t)args.targetOffset);

    /*
     * Allocate RWX memory and copy data for hook payload + trampoline
     */

    // Subtract one because we cannot have a ret instruction (0xC3) because we jump to the hook, we don't call it
    uint64_t hookFunctionSize = args.hookFunctionSize - 1;
    uint64_t trampolineSize   = args.trampolineSize;

    // Index for the "jump back" instruction, which should come immediately after the trampoline
    int jumpBackIndex         = hookFunctionSize + trampolineSize;

    // Allocate kernel heap memory for the payload, relying on userland is an extremely bad idea
    uint8_t *hookPayload = (uint8_t *)kmem_alloc(map, jumpBackIndex + 0x10);

    // Copy payload into the kernel buffer
    copyin(args.hookFunctionAddr, hookPayload, hookFunctionSize);

    // Debug breakpoints incase something fucked up
    for(int i = hookFunctionSize; i < hookFunctionSize + trampolineSize; i++)
        hookPayload[i] = 0xCC;

    // Create trampoline
    memcpy((char *)(hookPayload + hookFunctionSize), targetAddr, trampolineSize);

    // Jump back to original function post-hook and post-trampoline
    //  movabs r10, {target}  ; +0  = 49 ba XX XX XX XX XX XX XX XX
    //  jmp    r10            ; +10 = 41 ff e2
    hookPayload[jumpBackIndex + 0x0] = 0x49;
    hookPayload[jumpBackIndex + 0x1] = 0xBA;
    *(uint64_t *)(hookPayload + jumpBackIndex + 0x2) = (uint64_t)(targetAddr + trampolineSize);
    hookPayload[jumpBackIndex + 0xA] = 0x41;
    hookPayload[jumpBackIndex + 0xB] = 0xFF;
    hookPayload[jumpBackIndex + 0xC] = 0xE2;

    /*
     * Write dispatch entry
     */
    printf("[PS4-KHook] Installing dispatch entry of ID [%d] (hook function: %p | trampoline offset: 0x%llx)\n",
           args.id,
           hookPayload,
           args.hookFunctionSize);

    // Disable write protection
    writeCr0(cr0 & ~X86_CR0_WP);

    // The trampoline will always immediately follow the hook function
    dispatch->entries[args.id].payloadAddress = hookPayload;
    dispatch->entries[args.id].trampolineOffset = args.hookFunctionSize;

    // Re-enable write protection
    writeCr0(cr0);

    /*
     * Install hook
     */
    uint8_t *kmem = (uint8_t *)targetAddr;

    // We have to negate the value if the code cave is before the hook target
    int multiplier = 1;

    if((uint64_t)targetAddr > (uint64_t)KERNEL_DISPATCH_CODE_CAVE)
        multiplier = -1;

    // Calculate the RIP-relative offset. We have to add 6 bytes to account for the jump instruction's opcodes, since
    // jumps are relative to the *next* instruction.
    int32_t jumpTargetRipOffset = (int32_t)(((uint64_t)(targetAddr) + 10 - (uint64_t)(KERNEL_DISPATCH_CODE_CAVE)) * multiplier);

    printf("[PS4-KHook] Installing hook [ID: %d] @ %p (payload: %p)\n", args.id, targetAddr, hookPayload);

    // Disable write protection
    writeCr0(cr0 & ~X86_CR0_WP);

    // Setup indexer
    //   mov ax, {index} ; +0 = b8 XX 00 00 00
    kmem[0] = 0xB8;
    kmem[1] = (uint8_t)args.id;
    kmem[2] = 0x00;
    kmem[3] = 0x00;
    kmem[4] = 0x00;

    // Jump to hook payload
    //   jmp qword ptr {dispatch code rip relative} ; +5 = b9 XX XX XX XX
    kmem[5] = 0xE9;
    *(uint32_t *)(kmem + 6) = jumpTargetRipOffset;

    // Re-enable write protection
    writeCr0(cr0);
}
