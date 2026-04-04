#pragma once
#include <vector>
#include <optional>
#include <variant>
#include "vm_state.hpp"

namespace vmp {

// Forward declaration for LiftedRoutine
struct LiftedRoutine;

// Register extension helper - maps sub-registers to 64-bit parent
x86_reg extend_reg(x86_reg r);

// Reduce/deobfuscate a handler chunk
void reduce_chunk(VmState* vstate, disasm::Stream& is, 
    const std::vector<std::pair<RkeyBlock*, RkeyValue>>& parameters, 
    bool has_next);

// Update rolling key register
void update_vrk(VmState* state, const disasm::Stream& is);

// Update VIP direction
void update_vip_direction(VmState* state, const disasm::Stream& is);

// Find self-reference point
std::optional<uint64_t> find_self_ref(VmState* state, const disasm::Stream& is, int index);

// Parse VMENTER - returns stack layout and initial VIP
std::pair<std::vector<std::variant<x86_reg, uint64_t>>, uint64_t> 
    parse_vmenter(VmState* vstate, uint32_t rva_ep);

// Parse VMEXIT - returns popped register order
std::vector<std::variant<x86_reg, uint64_t>> parse_vmexit(VmState* vstate, const disasm::Stream& is);

// Parse VMSWAP - returns rkey blocks and prefix
std::vector<RkeyBlock> parse_vmswap(VmState* vstate, disasm::Stream& is, disasm::Stream& prefix_out);

// Extract rolling key blocks from stream
std::pair<int, RkeyBlock> extract_next_rkey_block(VmState* state, const disasm::Stream& is);
std::vector<RkeyBlock> extract_rkey_blocks(VmState* state, const disasm::Stream& is);

} // namespace vmp
