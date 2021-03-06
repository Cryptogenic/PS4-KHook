// PS4 KHook
// =========
// A hacky but minimal kernel hooking payload for PS4 (or any other x64 system really).
//
// A few notes important for hooking:
//   - Hook functions go in hooks.c w/ prototypes in hook.h
//   - Hooks must end in return 0x1337 and this payload must be compiled with -O0 for the get size routine to work
//   - Don't use multiple return paths in hooks
//   - Trampolines must be a minimum size of 0xA / 10 bytes
//   - Trampolines must not contain RIP-relative instructions (calls, jumps, RIP-relative reads/writes)
//
// Other notes:
//   - All offsets/values in here (including the code cave) are specific to 5.05, they will need to be modified for other
//     firmwares (or systems).
//
// TODO:
//   - Rework dispatch table to allow for a smaller code cave by pivoting to a heap-allocated dispatch table
//   - Fix up RIP-relative instructions to allow them inside trampolines
//   - Possibly do more robust function size calculation (size directives?)

#include <ps4.h>
#include <kernel.h>

#include "hooking.h"
#include "hooks.h"

#define HOOK_DYNLIB_PREPARE_DLCLOSE     0x00239380
#define HOOK_M_PULLUP                   0x000CA290

// get_function_size takes a function pointer as a uint8_t array and determines the size of the function at runtime.
// Note: It *requires* the function to return 0x1337 and -O0 optimization, or this function will fail to work properly
// and things will blow up.
uint64_t get_function_size(uint8_t *func)
{
    int idx = 0;

    for(int i = 0;;i++)
    {
        idx = i;

        // mov eax, 0x1337; leave; ret;
        if(func[idx++] == 0xB8)
            if(func[idx++] == 0x37)
                if(func[idx++] == 0x13)
                    if(func[idx++] == 0x00)
                        if(func[idx++] == 0x00)
                            if(func[idx++] == 0xC9)
                                if(func[idx++] == 0xC3)
                                    return idx;
    }
}

// Payload entry point.
int _main(struct thread *td)
{
    UNUSED(td);

    // In order to use kexec and other functions, we need to init the libkernel library
    initKernel();

    // We'll use a user-mapped buffer for arguments allocated at a fixed address. The reason for this is unfortunately args
    // couldn't get passed properly to kexec routines (not sure why at this time). So the kernel install hook function
    // dereferences the fixed address KEXEC_ARGS_BUFFER.
    char *kexecArgsBuffer = mmap(KEXEC_ARGS_BUFFER, 0x4000, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

    if(kexecArgsBuffer != KEXEC_ARGS_BUFFER)
        return -1;

    struct install_hook_args *installHookArgs = (struct install_hook_args *)kexecArgsBuffer;

    // Initialize the dispatch table in the code cave for hooks before installing anything. This includes the dispatching
    // thunk and default hook entries.
	kexec(&kernel_initialize_dispatch, NULL);

    // Install force GC
    installHookArgs->id = 1;
    installHookArgs->targetOffset = (uint64_t *)HOOK_DYNLIB_PREPARE_DLCLOSE;
    installHookArgs->trampolineSize = 0xA;
    installHookArgs->hookFunctionAddr = (uint64_t *)&call_gc;
    installHookArgs->hookFunctionSize = get_function_size((uint8_t *)&call_gc);

    kexec(&kernel_install_hook, NULL);

    // Install m_pullup hook
    installHookArgs->id = 2;
    installHookArgs->targetOffset = (uint64_t *)HOOK_M_PULLUP;
    installHookArgs->trampolineSize = 0xB;
    installHookArgs->hookFunctionAddr = (uint64_t *)&m_pullup_print;
    installHookArgs->hookFunctionSize = get_function_size((uint8_t *)&m_pullup_print);

	kexec(&kernel_install_hook, NULL);

	// Test GC hook
	dynlib_prepare_dlclose();

	// Uninstall force GC
    struct uninstall_hook_args *uninstallHookArgs = (struct uninstall_hook_args *)kexecArgsBuffer;

    uninstallHookArgs->id = 1;
    uninstallHookArgs->targetOffset = (uint64_t *)HOOK_DYNLIB_PREPARE_DLCLOSE;

    kexec(&kernel_uninstall_hook, NULL);

    sceKernelUsleep(200000);

    //kexec(&kernel_test, NULL);

    // Test that GC hook was uninstalled
    dynlib_prepare_dlclose();

	return 0;
}
