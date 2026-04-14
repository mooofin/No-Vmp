#include <capstone/capstone.h>
#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) return 0;

    x86_reg reg = static_cast<x86_reg>(data[0] % X86_REG_ENDING);

    x86_reg parent = X86_REG_INVALID;

    if (reg >= X86_REG_AH && reg <= X86_REG_AL)
        parent = X86_REG_RAX;
    else if (reg >= X86_REG_BPL && reg <= X86_REG_BL)
        parent = X86_REG_RBX;
    else if (reg >= X86_REG_SPL && reg <= X86_REG_DL)
        parent = X86_REG_RDX;
    else if (reg >= X86_REG_R8B && reg <= X86_REG_R8)
        parent = X86_REG_R8;
    else if (reg >= X86_REG_R15B && reg <= X86_REG_R15)
        parent = X86_REG_R15;
    else
        parent = reg;

    (void)parent;

    return 0;
}
