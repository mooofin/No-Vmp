wip: modern fork of NoVmp as my attempt to learning VMProtect internals

Replaced VTIL with an LLVM IR backend to better understand the lifting pipeline, and started implementing an early VMP to LLVM translation with the opcode table about halfway done. Refactored the codebase to use C++23 features like jthread, semaphore, span, and println, switched to using Capstone directly instead of the vtil::amd64 wrapper, added CLI11 for argument parsing, and introduced a shared_mutex based cache for deobfuscation experiments.



very early and not functional, mostly a learning exercise to understand VMProtect 3.x

original work by can1357