No-Vmp
======

No-Vmp tries to devirtualize VMProtect 3.x by lifting handlers into LLVM IR. It mostly works. Sometimes it doesn't. The point was understanding how VMProtect actually works under the hood.

This fork modernizes can1357's original code: CMake, C++23, all that. The old implementation sits in `legacy/` if you need it for reference. Not maintained, just there.

Building
--------

Straightforward enough:

    mkdir build && cd build
    cmake .. -DCMAKE_BUILD_TYPE=Release
    make -j$(nproc)

Usage
-----

Feed it an unpacked PE (MZ/PE headers, not ELF):

    ./build/novmp <file.exe> --output ./out

What's inside
-------------

`src/` has the CLI entrypoint. `lib/` has the actual work: disassembly glue, VM state tracking, emulator hooks for keys, and the LLVM backend. We use `linux-pe` for PE parsing because life's too short to write another PE parser.

Status
------

Incomplete. Some binaries lift fine, others break, and VMProtect keeps changing. Main goal is figuring out the internals and getting IR you can actually read. Don't expect too much.

Credits to can1357.
