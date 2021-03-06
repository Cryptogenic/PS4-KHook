# PS4 KHook
[![API Version Compatibility](https://img.shields.io/badge/PS4%20Firmware%20Target-5.05-blue.svg)]()

PS4 KHook is a minimalist kernel hooking payload. It targets 5.05 but it can be used with any firmware (or even non-PS4 systems) with modifications. It's primary intent is for exploit development / debugging though it can be used anywhere hooking is needed (though Mira is recommended for long-term hooks for things like homebrew). It doesn't require a daemon to run for state tracking as it uses a code cave and a dispatch table.

Warning: the implementation is pretty hacky and it's not yet complete. Feel free to fork and pull request any improvements or TODO items.

## Building and running
To build this payload you'll need the [PS4 Payload SDK from Scene Collective](https://github.com/Scene-Collective/ps4-payload-sdk). Once installed, simply build this payload like so:
```
$ make clean
$ make
$ cat PS4-KHook.bin | nc [ps4ip:payloadport]
```

## Important caveats
This hooking payload does have some caveats you need to be aware of before writing and installing hooks.
- Hooks must only have one return path, and it must return 0x1337. Additionally, the payload must be compiled without optimization (-O0). The reason for this is due to the runtime function size calculation for the hooks.
- Trampolines must be a minimum size of 10 bytes (0xA bytes).
- Trampolines cannot contain any instructions that use RIP-relative addressing (including calls, jumps, or RIP-relative data reads/writes).
- Kernel offsets and the code cave are for 5.05 firmware. To use this on other firmwares you'll need to port these offsets.

## Adding your own hooks
Hooks should be defined in `hooks.c` with prototypes in `hooks.h`. These files already have two example hooks I wrote for debugging stuff with the IP6_EXTHDR_CHECK UAF from theflow. Use the following template for hook functions:

```c
int my_hook()
{
    SAVE_REGISTERS;
    
    // [hook code]

    RESTORE_REGISTERS;
    return 0x1337;
}
```

For installing hooks, reference `main.c`. Here's an example for installing `my_hook` on the `sys_dynlib_prepare_dlclose` syscall with hook ID 1:
```c
#define HOOK_DYNLIB_PREPARE_DLCLOSE     0x239380

// ...

char *kexecArgsBuffer = mmap(KEXEC_ARGS_BUFFER, 0x4000, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

if(kexecArgsBuffer != KEXEC_ARGS_BUFFER)
    return -1;

struct install_hook_args *installHookArgs = (struct install_hook_args *)kexecArgsBuffer;

installHookArgs->id = 1;
installHookArgs->targetOffset = (uint64_t *)HOOK_DYNLIB_PREPARE_DLCLOSE;
installHookArgs->trampolineSize = 0xA;
installHookArgs->hookFunctionAddr = (uint64_t *)&my_hook;
installHookArgs->hookFunctionSize = get_function_size((uint8_t *)&my_hook);
```

The argument that will require some manual work to figure out and ensure you set properly is the trampoline size, since it cannot be automatically calculated, it's dependent on where you hook. This is because x86 has variable sized instructions, so if your trampoline size is incorrect, a crash will occur due to executing invalid instructions (or valid instructions that have unintended behavior).

Again, keep in mind it has to be at least 0xA size and possibly larger depending on the instructions at the hook location.

## TODO

- 

## License
Specter (Cryptogenic) - [@SpecterDev](https://twitter.com/specterdev)

This project is licensed under the WTFPL license - see the [LICENSE.md](LICENSE.md) file for details.

## Thanks
- [@tihmstar](https://twitter.com/tihmstar)
- [@littlelailo](https://twitter.com/littlelailo)
