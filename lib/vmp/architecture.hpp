#pragma once
#include <string>
#include <vector>
#include <set>
#include <cstdint>
#include "vm_state.hpp"
#include "../disasm/stream.hpp"

namespace vmp::arch {

// Size abbreviation helpers — strongly typed now.
enum class OpSize : uint8_t { B=1, W=2, D=4, Q=8 };
[[nodiscard]] char     to_char(OpSize s) noexcept;
[[nodiscard]] OpSize   from_char(char c);

constexpr int32_t kUnknownDelta = 0x1000'0000;

// Classified VMP IL instruction (opcode + decoded parameters).
struct Instruction {
    std::string            op;               // e.g. "VPUSH", "VADD", "VJMP"
    disasm::Stream         handler_stream;   // raw x86 of the handler (for vemit fallback)

    std::vector<uint64_t>  params;           // decrypted immediate params
    std::vector<OpSize>    param_sizes;

    // Stack effect summary.
    int32_t                stack_delta  = 0;
    std::set<int32_t>      stack_reads;
    std::set<int32_t>      stack_writes;

    // Virtual-register effect summary.
    std::set<uint8_t>      ctx_reads;
    std::set<uint8_t>      ctx_writes;
};

// Classify a decoded handler stream + parameters into an Instruction.
[[nodiscard]] Instruction classify(VmState* state, const disasm::Stream& stream);

} // namespace vmp::arch
