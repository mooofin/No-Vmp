#pragma once
#include <vector>
#include <optional>
#include <variant>
#include "vm_state.hpp"
#include "../disasm/stream.hpp"
#include "../emulator/emulator.hpp"

namespace vmp {

// Helper to extend register to 64-bit parent
x86_reg extend_reg(x86_reg r);

// Extract next rolling key block
std::pair<int, RkeyBlock> extract_next_rkey_block(VmState* state,
                                                   const disasm::Stream& is,
                                                   int index = 0);

// Extract all rolling key blocks
std::vector<RkeyBlock> extract_rkey_blocks(VmState* vstate,
                                          const disasm::Stream& is);

} // namespace vmp
