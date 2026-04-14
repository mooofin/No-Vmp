#pragma once
#include <vector>
#include <span>
#include <cstdint>
#include <memory>
#include <linuxpe>

// Include LiftContext definition
#include "../ir/context.hpp"

namespace vmp {

// Result structure for lifted routine
struct LiftedRoutine {
    std::unique_ptr<ir::LiftContext> context;
    size_t handler_count = 0;
    size_t instructions_before = 0;
    size_t instructions_after = 0;
};

struct VirtualRoutine {
    uint32_t                       jmp_rva     = 0;
    bool                           mid_routine = false;
    std::unique_ptr<LiftedRoutine> result;       // filled after lifting
};

struct LiftOptions {
    bool optimize              = true;
    bool strip_const_obfusc   = false;
    bool experimental_recompile = false;
};

class ImageDesc {
public:
    explicit ImageDesc(std::vector<uint8_t> raw, uint64_t override_base = 0);

    // PE navigation — non-owning views into raw_.
    [[nodiscard]] win::image_x64_t*    pe()         noexcept;
    [[nodiscard]] win::nt_headers_x64_t* nt_hdrs()  noexcept;
    [[nodiscard]] const win::nt_headers_x64_t* nt_hdrs() const noexcept;
    [[nodiscard]] uint64_t             image_base()  const noexcept;
    [[nodiscard]] bool                 has_relocs()  const noexcept { return has_relocs_; }
    [[nodiscard]] std::span<uint8_t>   raw()         noexcept { return raw_; }

    template<typename T = void>
    [[nodiscard]] T* rva_to_ptr(uint32_t rva) noexcept {
        return pe()->rva_to_ptr<T>(rva);
    }
    [[nodiscard]] win::section_header_t* rva_to_section(uint32_t rva) noexcept;

    // Scan executable sections for VMEnter patterns; fills virt_routines_.
    void discover_vmenter();

    // Override with explicit RVA list.
    void set_target_rvas(std::span<const uint32_t> rvas);

    [[nodiscard]] std::span<VirtualRoutine>       routines()       noexcept;
    [[nodiscard]] std::span<const VirtualRoutine> routines() const noexcept;

    LiftOptions opts;

private:
    std::vector<uint8_t>          raw_;
    uint64_t                      override_base_ = 0;
    bool                          has_relocs_    = false;
    std::vector<VirtualRoutine>   virt_routines_;
};

} // namespace vmp
