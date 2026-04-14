No-Vmp
======

Devirtualize VMProtect 3.x. Lift handlers to LLVM IR. Works sometimes.

Build
-----

Needs LLVM, Capstone installed.

    bazel build //:novmp

Test
----

    bazel test //...

Usage
-----

Feed unpacked PE:

    bazel run //:novmp -- <file.exe> -o ./out

Structure
---------

- `src/`: CLI entry
- `lib/vmp/`: VM analysis + IR lifting
- `lib/disasm/`: Capstone glue
- `lib/emulator/`: x86 emu for keys
- `tests/`: gtest unit tests
- `third_party/`: linux-pe parser

Status
------

Incomplete. VMProtect changes. Goal is readable IR, not perfect deobfuscation.

Credits: can1357 (original)
