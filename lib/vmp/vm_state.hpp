#pragma once
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <capstone/capstone.h>
#include "image_desc.hpp"
#include "../disasm/stream.hpp"

namespace vmp {

using RollingKey = uint64_t;

// Decrypted parameter value from VIP stream.
struct RkeyValue {
    uint64_t raw  = 0;
    uint32_t size = 0;   // bytes: 1|2|4|8

    [[nodiscard]] int64_t  as_signed()   const noexcept;
    [[nodiscard]] uint64_t as_unsigned() const noexcept;
};

// One rolling-key decryption block identified in a handler's instruction stream.
struct RkeyBlock {
    x86_reg  output_reg        = X86_REG_INVALID;
    x86_reg  rolling_key_reg   = X86_REG_INVALID;
    std::pair<int,uint64_t> block_start{};
    std::pair<int,uint64_t> block_end{};
    uint32_t output_size       = 0;

    // Captured emulation thunk — no raw function pointers, clean std::function.
    std::function<std::pair<RkeyValue, RollingKey>(const void* src, RollingKey k)> decrypt;
};

// Direction of the virtual instruction pointer stream.
enum class VipDirection : int8_t { Unknown = 0, Forward = +1, Backward = -1 };

struct VmState {
    ImageDesc*  img                 = nullptr;
    uint32_t    handler_rva         = 0;
    uint64_t    vip                 = 0;          // current virtual IP (RVA)
    x86_reg     reg_vip             = X86_REG_INVALID;
    x86_reg     reg_vsp             = X86_REG_INVALID;
    x86_reg     reg_vrk             = X86_REG_INVALID;
    VipDirection dir_vip            = VipDirection::Unknown;
    RollingKey  rolling_key         = 0;

    // Unroll and cache current handler stream.
    [[nodiscard]] disasm::Stream unroll() const;

    // Raw VIP access.
    [[nodiscard]] const uint8_t* peek_vip(uint32_t num_bytes = 0) const;
    [[nodiscard]] const uint8_t* read_vip(uint32_t num_bytes);

    // Decrypt one parameter from VIP stream.
    [[nodiscard]] RkeyValue decrypt_vip(RkeyBlock& block, uint32_t num_bytes = 0);

    // Advance to next serial instruction.
    void advance(RkeyValue delta);

    // Advance to next branching / VMENTER instruction.
    void advance(RkeyBlock& off_block, uint64_t new_vip, uint32_t self_ref_rva);

private:
    [[nodiscard]] int8_t dir() const noexcept {
        return static_cast<int8_t>(dir_vip);
    }
};

} // namespace vmp
