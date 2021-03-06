#include "hooking.h"

struct mbuf {
    struct mbuf *mh_next;
    struct mbuf *mh_nextpkt;
    char *mh_data;
    char pad[256 - (0x8 * 3)];
};

// call_gc is a hook payload to forcefully wakeup the pagedaemon to trigger page reclaiming in UMA.
int call_gc(uint64_t rdi, uint64_t rsi, uint64_t rdx, uint64_t rcx, uint64_t r8, uint64_t r9)
{
    SAVE_REGISTERS;

    // Resolve symbols
    void (*printf)(char *format, ...) = (void (*)(char *, ...))(KERNEL_PRINTF);
    void (*pagedaemon_wakeup)(int id) = (void (*)(int))(KERNEL_PAGEDAEMON_WAKEUP);

    // Format strings *must* be kept in kernel space, so we'll put it on the stack
    char strData[] = "[PS4-KHook] Waking up the page daemon and freeing pages!\n\x00";
    printf(strData);

    // Invoke the GC routine
    for (int i=0; i< 4; i++)
        pagedaemon_wakeup(i);

    RESTORE_REGISTERS;

    // DO NOT CHANGE THIS VALUE OR SHIT WILL BREAK
    return 0x1337;
}

// m_pullup_print is a hook payload that prints debugging info inside of m_pullup for mbuf rearrangement.
int m_pullup_print(uint64_t rdi, uint64_t rsi, uint64_t rdx, uint64_t rcx, uint64_t r8, uint64_t r9)
{
    SAVE_REGISTERS;

    // Resolve symbols
    void (*printf)(char *format, ...) = (void (*)(char *, ...))(KERNEL_PRINTF);

    // Get the current thread structure from gs:0 as well as the mbuf pointer from r12
    uint8_t *td = 0;
    struct mbuf *mbufPtr;

    asm("mov %%gs:0, %0\n\t" : "=r" (td));
    asm("mov %%r12, %0\n\t" : "=r" (mbufPtr));

    // Print the mbuf being free'd, it's first dword of data, and the current + last CPU core
    char strData[] = "[PS4-KHook] mbuf %p is being free'd (data '0x%08x') (cpu: %d | last cpu: %d)\n\x00";

    // Sometimes mbuf is null so we have to check or we'll blow up
    if(mbufPtr != 0)
    {
        uint32_t *mhData = (uint32_t *)mbufPtr->mh_data;

        // td->td_oncpu   = offset 0xF8
        // td->td_lastcpu = offset 0xF8
        printf(strData, mbufPtr, mhData[0], td[0xF9], td[0xF8]);
    }

    RESTORE_REGISTERS;

    // DO NOT CHANGE THIS VALUE OR SHIT WILL BREAK
    return 0x1337;
}