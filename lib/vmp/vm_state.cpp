#include "vm_state.hpp"
#include <stdexcept>
#include <format>

namespace vmp {

int64_t RkeyValue::as_signed() const noexcept {
    switch (size) {
        case 8: return static_cast<int64_t>(raw);
        case 4: return static_cast<int32_t>(raw);
        case 2: return static_cast<int16_t>(raw);
        case 1: return static_cast<int8_t>(raw);
        default: return static_cast<int64_t>(raw);
    }
}

uint64_t RkeyValue::as_unsigned() const noexcept {
    return raw;
}

disasm::Stream VmState::unroll() const {
    // Create a Deobfuscator with the image's RVA-to-pointer resolver
    disasm::Deobfuscator deob([this](uint32_t rva) -> const uint8_t* {
        return img->rva_to_ptr<uint8_t>(rva);
    });
    
    return deob.get(handler_rva);
}

const uint8_t* VmState::peek_vip(uint32_t num_bytes) const {
    if (dir_vip == VipDirection::Backward) {
        // Explicit comparison to avoid overflow/underflow edge cases
        if (vip < static_cast<uint64_t>(num_bytes)) {
            throw std::runtime_error("VIP underflow in backward stream");
        }
        return img->rva_to_ptr<uint8_t>(static_cast<uint32_t>(vip - num_bytes));
    } else if (dir_vip == VipDirection::Forward) {
        return img->rva_to_ptr<uint8_t>(static_cast<uint32_t>(vip));
    } else {
        throw std::runtime_error("VIP direction unknown");
    }
}

const uint8_t* VmState::read_vip(uint32_t num_bytes) {
    const uint8_t* ret = peek_vip(num_bytes);
    if (!ret) {
        throw std::runtime_error("Invalid VIP read");
    }
    vip += static_cast<int64_t>(num_bytes) * dir();
    return ret;
}

RkeyValue VmState::decrypt_vip(RkeyBlock& block, uint32_t num_bytes) {
    // Use block's output_size if num_bytes not specified
    if (num_bytes == 0) {
        num_bytes = block.output_size;
    } else if (num_bytes != block.output_size) {
        throw std::runtime_error("RkeyBlock size mismatch");
    }
    
    // Read encrypted bytes from VIP stream
    const uint8_t* encrypted = read_vip(num_bytes);
    
    // Decrypt using the captured function
    auto [value, new_key] = block.decrypt(encrypted, rolling_key);
    
    // Update rolling key
    rolling_key = new_key;
    
    return value;
}

void VmState::advance(RkeyValue delta) {
    // Delta for serial instructions should be 4 bytes (int32_t offset)
    if (delta.size != 4) {
        throw std::runtime_error("Invalid delta size for serial advance");
    }
    
    // Calculate new handler RVA based on the decrypted offset
    handler_rva += static_cast<int32_t>(delta.as_signed());
}

void VmState::advance(RkeyBlock& off_block, uint64_t new_vip, uint32_t self_ref_rva) {
    // Offset decryption blocks are always 4 bytes
    if (off_block.output_size != 4) {
        throw std::runtime_error("Invalid offset block size");
    }
    
    // Set new VIP
    vip = new_vip;
    
    // Calculate new rolling key
    rolling_key = new_vip + img->image_base();
    
    // Decrypt the handler offset
    auto offset = decrypt_vip(off_block, 4);
    
    // Calculate new handler RVA
    handler_rva = self_ref_rva + static_cast<int32_t>(offset.as_signed());
}

} // namespace vmp
