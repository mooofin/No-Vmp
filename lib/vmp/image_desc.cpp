#include "image_desc.hpp"
#include <stdexcept>
#include <algorithm>
#include <cstring>

namespace vmp {

ImageDesc::ImageDesc(std::vector<uint8_t> raw, uint64_t override_base)
    : raw_(std::move(raw)), override_base_(override_base) {
    
    // Validate PE header
    if (raw_.size() < sizeof(win::image_x64_t)) {
        throw std::runtime_error("File too small for PE header");
    }
    
    auto* pe = this->pe();
    if (pe->dos_header.e_magic != win::DOS_HDR_MAGIC) {
        throw std::runtime_error("Invalid DOS header magic");
    }
    
    auto* nt = nt_hdrs();
    if (nt->signature != win::NT_HDR_MAGIC) {
        throw std::runtime_error("Invalid NT headers signature");
    }
    
    // Check for relocations
    has_relocs_ = nt->optional_header.data_directories.basereloc_directory.present();
    if (override_base_ != 0) {
        has_relocs_ = true; // Assume relocatable if base is overridden
    }
}

win::image_x64_t* ImageDesc::pe() noexcept {
    return reinterpret_cast<win::image_x64_t*>(raw_.data());
}

win::nt_headers_x64_t* ImageDesc::nt_hdrs() noexcept {
    return pe()->get_nt_headers();
}

const win::nt_headers_x64_t* ImageDesc::nt_hdrs() const noexcept {
    return const_cast<ImageDesc*>(this)->pe()->get_nt_headers();
}

uint64_t ImageDesc::image_base() const noexcept {
    if (override_base_ != 0) return override_base_;
    return nt_hdrs()->optional_header.image_base;
}

win::section_header_t* ImageDesc::rva_to_section(uint32_t rva) noexcept {
    return pe()->rva_to_section(rva);
}

void ImageDesc::discover_vmenter() {
    virt_routines_.clear();
    
    auto* nt = nt_hdrs();
    if (!nt) return;
    
    // Iterate each section
    for (int i = 0; i < nt->file_header.num_sections; i++) {
        auto* scn = nt->get_section(i);
        if (!scn) continue;
        
        // Skip if not executable
        if (!scn->characteristics.mem_execute) continue;
        
        // Calculate section bounds
        uint8_t* scn_begin = raw_.data() + scn->ptr_raw_data;
        size_t scn_size = std::min(static_cast<size_t>(scn->size_raw_data), 
                                   static_cast<size_t>(scn->virtual_size));
        uint8_t* scn_end = scn_begin + scn_size;
        
        if (scn_size < 10) continue;
        
        // Scan for JMP rel32 (0xE9) or CALL rel32 (0xE8)
        for (uint8_t* it = scn_begin; it < scn_end - 10; it++) {
            bool mid_func = false;
            
            if (it[0] == 0xE9) {
                mid_func = true; // JMP
            } else if (it[0] == 0xE8) {
                mid_func = false; // CALL
            } else {
                continue;
            }
            
            // Compute jump target RVA - use memcpy to avoid strict aliasing UB
            int32_t rel32;
            std::memcpy(&rel32, &it[1], sizeof(rel32));
            uint32_t jmp_rva = scn->virtual_address + (it - scn_begin) + 5 + rel32;
            
            // Skip if target is in the same section
            if (jmp_rva >= scn->virtual_address && 
                jmp_rva < scn->virtual_address + scn->virtual_size) {
                continue;
            }
            
            // Skip if target is in a non-executable section
            auto* scn_jmp = rva_to_section(jmp_rva);
            if (!scn_jmp || !scn_jmp->characteristics.mem_execute) {
                continue;
            }
            
            // Check for VMEnter pattern: PUSH imm32 followed by CALL rel32
            // At target: 0x68 (PUSH imm32) at offset 0, 0xE8 (CALL rel32) at offset 5
            uint8_t* jmp_target_bytes = rva_to_ptr<uint8_t>(jmp_rva);
            if (!jmp_target_bytes) continue;
            
            // Bounds check
            if (jmp_target_bytes > raw_.data() + raw_.size() - 10) continue;
            
            // Check for 0x68 (PUSH imm32) followed by 0xE8 (CALL rel32)
            if (jmp_target_bytes[0] != 0x68 || jmp_target_bytes[5] != 0xE8) {
                continue;
            }
            
            // Found VMEnter!
            virt_routines_.push_back(VirtualRoutine{
                .jmp_rva = jmp_rva,
                .mid_routine = mid_func,
                .result = nullptr
            });
        }
    }
}

void ImageDesc::set_target_rvas(std::span<const uint32_t> rvas) {
    virt_routines_.clear();
    for (uint32_t rva : rvas) {
        virt_routines_.push_back(VirtualRoutine{
            .jmp_rva = rva,
            .mid_routine = false,
            .result = nullptr
        });
    }
}

std::span<VirtualRoutine> ImageDesc::routines() noexcept {
    return std::span(virt_routines_);
}

std::span<const VirtualRoutine> ImageDesc::routines() const noexcept {
    return std::span(virt_routines_);
}

} // namespace vmp
