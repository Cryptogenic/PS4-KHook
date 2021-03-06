#pragma once
#ifndef HOOKING_H
#define HOOKING_H

#include <payload_utils.h>
#include <fw_defines.h>

#define KERNEL_BASE &((uint8_t *)__readmsr(0xC0000082))[-K505_XFAST_SYSCALL]

#define KERNEL_PRINTF               KERNEL_BASE + 0x00436040
#define KERNEL_SNPRINTF             KERNEL_BASE + 0x00436350
#define KERNEL_DISPATCH_CODE_CAVE   KERNEL_BASE + 0x00017260 // hammer_time
#define KERNEL_MEMCPY               KERNEL_BASE + 0x001EA530
#define KERNEL_COPYIN               KERNEL_BASE + 0x001EA710
#define KERNEL_MAP                  KERNEL_BASE + 0x01AC60E0
#define KERNEL_KMEM_ALLOC           KERNEL_BASE + 0x000FCC80
#define KERNEL_PAGEDAEMON_WAKEUP    KERNEL_BASE + 0x001EE240

#define KEXEC_ARGS_BUFFER           (void *)0xDEAD0000

#define CREATE_FMT_STR(BUF, STR) \
    for(int i = 0;;i++) {        \
        if(STR[i] == '\x00') {   \
            break;               \
        }                        \
        BUF[i] = STR[i];         \
    }

#define SAVE_REGISTERS      \
    asm(                    \
        "push %rbx\n\t"     \
        "push %r12\n\t"     \
        "push %r13\n\t"     \
        "push %r14\n\t"     \
        "push %r15\n\t"     \
        "push %rax\n\t"     \
        "push %rdi\n\t"     \
        "push %rsi\n\t"     \
        "push %rdx\n\t"     \
        "push %rcx\n\t"     \
        "push %r8\n\t"      \
        "push %r9\n\t"      \
        "push %r10\n\t"     \
        "push %r11\n\t"     \
    )

#define RESTORE_REGISTERS   \
    asm(                    \
        "pop %r11\n\t"      \
        "pop %r10\n\t"      \
        "pop %r9\n\t"       \
        "pop %r8\n\t"       \
        "pop %rcx\n\t"      \
        "pop %rdx\n\t"      \
        "pop %rsi\n\t"      \
        "pop %rdi\n\t"      \
        "pop %rax\n\t"      \
        "pop %r15\n\t"      \
        "pop %r14\n\t"      \
        "pop %r13\n\t"      \
        "pop %r12\n\t"      \
        "pop %rbx\n\t"      \
    )

struct hook_dispatch_entry
{
    void *payloadAddress;
    uint64_t trampolineOffset;
};

struct dispatch_table
{
    char relayCode[0x20];
    struct hook_dispatch_entry entries[0x22];
};

struct install_hook_args
{
    uint16_t id;
    uint64_t *targetOffset;
    uint64_t trampolineSize;
    uint64_t *hookFunctionAddr;
    uint64_t hookFunctionSize;
};

void kernel_initialize_dispatch(struct thread *td, void *argsUnused);
void kernel_install_hook(struct thread *td, void *argsUnused);

#endif