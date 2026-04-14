#include <vector>
#include "stream.hpp"
#include <algorithm>
#include <stdexcept>
#include <cstring>
#include <array>
#include <unordered_set>

namespace vmp::disasm {

Insn::Insn(const cs_insn& insn) : raw(insn) {
    if (insn.detail) {
        detail_copy = *insn.detail;
        raw.detail = &*detail_copy;
    } else {
        raw.detail = nullptr;
    }
}

Insn::Insn(const Insn& other) : raw(other.raw), detail_copy(other.detail_copy) {
    raw.detail = detail_copy ? &*detail_copy : nullptr;
}

Insn& Insn::operator=(const Insn& other) {
    if (this == &other) return *this;
    raw = other.raw;
    detail_copy = other.detail_copy;
    raw.detail = detail_copy ? &*detail_copy : nullptr;
    return *this;
}

Insn::Insn(Insn&& other) noexcept
    : raw(other.raw), detail_copy(std::move(other.detail_copy)) {
    raw.detail = detail_copy ? &*detail_copy : nullptr;
    other.raw.detail = nullptr;
}

Insn& Insn::operator=(Insn&& other) noexcept {
    if (this == &other) return *this;
    raw = other.raw;
    detail_copy = std::move(other.detail_copy);
    raw.detail = detail_copy ? &*detail_copy : nullptr;
    other.raw.detail = nullptr;
    return *this;
}

// Insn implementation
bool Insn::is(unsigned id, std::span<const x86_op_type> ops) const noexcept {
    if (raw.id != id) return false;
    if (!raw.detail) return ops.empty();
    
    const auto& x86 = raw.detail->x86;
    if (x86.op_count != ops.size()) return false;
    
    for (size_t i = 0; i < ops.size(); ++i) {
        if (x86.operands[i].type != ops[i]) return false;
    }
    return true;
}

std::string Insn::to_string() const {
    return std::string(raw.mnemonic) + " " + std::string(raw.op_str);
}

std::span<const cs_x86_op> Insn::operands() const noexcept {
    if (!raw.detail) return {};
    const auto& x86 = raw.detail->x86;
    return std::span(x86.operands, x86.op_count);
}

std::span<const uint8_t> Insn::bytes() const noexcept {
    return std::span(raw.bytes, raw.size);
}

// Stream implementation
Stream Stream::operator+(const Stream& rhs) const {
    Stream out;
    std::unordered_set<int> pushed;
    
    for (const auto& entries : {entries_, rhs.entries_}) {
        for (const auto& entry : entries) {
            if (pushed.insert(entry.first).second) {
                out.entries_.push_back(entry);
            }
        }
    }
    
    return out.normalize();
}

Stream& Stream::normalize() {
    std::sort(entries_.begin(), entries_.end(),
        [](const auto& a, const auto& b) { return a.first < b.first; });
    return *this;
}

std::vector<uint8_t> Stream::to_bytes() const {
    // Make a copy since normalize() is non-const
    Stream temp(*this);
    temp.normalize();
    
    std::vector<uint8_t> raw;
    for (const auto& entry : temp.entries_) {
        const auto& insn_bytes = entry.second.bytes();
        raw.insert(raw.end(), insn_bytes.begin(), insn_bytes.end());
    }
    return raw;
}

int Stream::find_next(unsigned id, std::span<const x86_op_type> ops, int from) const {
    for (int i = from; i < static_cast<int>(entries_.size()); ++i) {
        if (entries_[i].second.is(id, ops)) return i;
    }
    return -1;
}

int Stream::find_prev(unsigned id, std::span<const x86_op_type> ops, int from) const {
    if (from == -1) from = static_cast<int>(entries_.size()) - 1;
    for (int i = from; i >= 0; --i) {
        if (entries_[i].second.is(id, ops)) return i;
    }
    return -1;
}

// Helper: check if two registers are the same extended family
static bool same_reg_family(x86_reg a, x86_reg b) {
    // Map any sub-register to its 64-bit parent
    auto extend = [](x86_reg r) -> x86_reg {
        switch (r) {
            // AL/AH/AX/EAX -> RAX
            case X86_REG_AL: case X86_REG_AH: case X86_REG_AX: case X86_REG_EAX:
                return X86_REG_RAX;
            // BL/BH/BX/EBX -> RBX
            case X86_REG_BL: case X86_REG_BH: case X86_REG_BX: case X86_REG_EBX:
                return X86_REG_RBX;
            // CL/CH/CX/ECX -> RCX
            case X86_REG_CL: case X86_REG_CH: case X86_REG_CX: case X86_REG_ECX:
                return X86_REG_RCX;
            // DL/DH/DX/EDX -> RDX
            case X86_REG_DL: case X86_REG_DH: case X86_REG_DX: case X86_REG_EDX:
                return X86_REG_RDX;
            // SIL/SI/ESI -> RSI
            case X86_REG_SIL: case X86_REG_SI: case X86_REG_ESI:
                return X86_REG_RSI;
            // DIL/DI/EDI -> RDI
            case X86_REG_DIL: case X86_REG_DI: case X86_REG_EDI:
                return X86_REG_RDI;
            // BPL/BP/EBP -> RBP
            case X86_REG_BPL: case X86_REG_BP: case X86_REG_EBP:
                return X86_REG_RBP;
            // SPL/SP/ESP -> RSP
            case X86_REG_SPL: case X86_REG_SP: case X86_REG_ESP:
                return X86_REG_RSP;
            // R8B/R8W/R8D -> R8
            case X86_REG_R8B: case X86_REG_R8W: case X86_REG_R8D:
                return X86_REG_R8;
            // R9B/R9W/R9D -> R9
            case X86_REG_R9B: case X86_REG_R9W: case X86_REG_R9D:
                return X86_REG_R9;
            // R10B/R10W/R10D -> R10
            case X86_REG_R10B: case X86_REG_R10W: case X86_REG_R10D:
                return X86_REG_R10;
            // R11B/R11W/R11D -> R11
            case X86_REG_R11B: case X86_REG_R11W: case X86_REG_R11D:
                return X86_REG_R11;
            // R12B/R12W/R12D -> R12
            case X86_REG_R12B: case X86_REG_R12W: case X86_REG_R12D:
                return X86_REG_R12;
            // R13B/R13W/R13D -> R13
            case X86_REG_R13B: case X86_REG_R13W: case X86_REG_R13D:
                return X86_REG_R13;
            // R14B/R14W/R14D -> R14
            case X86_REG_R14B: case X86_REG_R14W: case X86_REG_R14D:
                return X86_REG_R14;
            // R15B/R15W/R15D -> R15
            case X86_REG_R15B: case X86_REG_R15W: case X86_REG_R15D:
                return X86_REG_R15;
            default:
                return r;
        }
    };
    return extend(a) == extend(b);
}

TraceResult trace_def(const Stream& stream, x86_reg target_reg, int end, int begin) {
    std::unordered_set<x86_reg> dependencies;
    Stream substream;
    
    for (int i = end; i >= begin; --i) {
        const auto& ins = stream.entries()[i].second;
        bool read = false;
        bool write = false;
        std::vector<x86_reg> access_list;
        
        for (const auto& op : ins.operands()) {
            if (op.type == X86_OP_REG) {
                auto reg = op.reg;
                if (!same_reg_family(reg, target_reg)) {
                    access_list.push_back(reg);
                    continue;
                }
                read |= (op.access & CS_AC_READ) != 0;
                write |= (op.access & CS_AC_WRITE) != 0;
            }
            else if (op.type == X86_OP_MEM) {
                for (auto reg : {op.mem.base, op.mem.index}) {
                    if (reg == X86_REG_INVALID) continue;
                    if (!same_reg_family(reg, target_reg)) {
                        access_list.push_back(reg);
                        continue;
                    }
                    read |= (op.access & CS_AC_READ) != 0;
                }
            }
        }
        
        if (write) {
            for (auto reg : access_list) {
                if (reg != X86_REG_INVALID) dependencies.insert(reg);
            }
            substream.entries().push_back(stream.entries()[i]);
        }
        
        if (write && !read) break;
    }
    
    std::vector<x86_reg> deps;
    deps.reserve(dependencies.size());
    for (auto reg : dependencies) {
        deps.push_back(reg);
    }
    
    TraceResult result;
    result.defs = substream.normalize();
    result.deps = deps;
    return result;
}

void Stream::erase_front(int n) {
    if (n <= 0 || entries_.empty()) return;
    const auto erase_count = std::min<std::size_t>(static_cast<std::size_t>(n), entries_.size());
    entries_.erase(entries_.begin(), entries_.begin() + static_cast<std::ptrdiff_t>(erase_count));
}

void Stream::erase_range(int start, int end) {
    if (start < 0) start = 0;
    if (end > static_cast<int>(entries_.size())) end = static_cast<int>(entries_.size());
    if (start >= end) return;
    
    entries_.erase(entries_.begin() + start, entries_.begin() + end);
}

void Stream::truncate_at(int index) {
    if (index < 0 || index >= static_cast<int>(entries_.size())) return;
    entries_.erase(entries_.begin() + index, entries_.end());
}

std::string Stream::dump() const {
    std::string out;
    for (const auto& entry : entries_) {
        out += entry.second.to_string() + "\n";
    }
    return out;
}

// Deobfuscator implementation
struct Deobfuscator::Impl {
    RvaToPtr resolver;
    std::shared_mutex mutex;
    std::unordered_map<uint32_t, Stream> cache;
    csh cs_handle = 0;
    
    explicit Impl(RvaToPtr resolver) : resolver(resolver) {
        if (cs_open(CS_ARCH_X86, CS_MODE_64, &cs_handle) != 0) {
            throw std::runtime_error("Failed to open Capstone");
        }
        cs_option(cs_handle, CS_OPT_DETAIL, CS_OPT_ON);
    }
    
    ~Impl() {
        if (cs_handle) cs_close(&cs_handle);
    }
};

Deobfuscator::Deobfuscator(RvaToPtr resolver) 
    : impl_(std::make_unique<Impl>(resolver)) {}

Deobfuscator::~Deobfuscator() = default;

Stream Deobfuscator::get(uint32_t rva) {
    // Try read lock first
    {
        std::shared_lock lock(impl_->mutex);
        auto it = impl_->cache.find(rva);
        if (it != impl_->cache.end()) return it->second;
    }
    
    // Need to disassemble - take write lock
    std::unique_lock lock(impl_->mutex);
    
    // Double-check after acquiring write lock
    auto it = impl_->cache.find(rva);
    if (it != impl_->cache.end()) return it->second;
    
    auto& output = impl_->cache[rva];
    if (!output.empty()) return output;
    
    uint32_t rva_rip = rva;
    int instruction_idx = 0;
    std::vector<uint64_t> call_return_stack;
    std::unordered_set<uint64_t> seen_states;
    static constexpr size_t kMaxSteps = 0x20000;
    size_t steps = 0;
    
    while (true) {
        if (++steps > kMaxSteps) {
            throw std::runtime_error("Deobfuscation step budget exceeded");
        }

        const uint64_t state_key =
            (static_cast<uint64_t>(rva_rip) << 8) ^ (call_return_stack.size() & 0xFFull);
        if (!seen_states.insert(state_key).second) {
            throw std::runtime_error("Deobfuscation loop detected");
        }

        const uint8_t* code = impl_->resolver(rva_rip);
        if (!code) {
            throw std::runtime_error("Invalid RVA in deobfuscate");
        }
        
        cs_insn* insn;
        size_t count = cs_disasm(impl_->cs_handle, code, 16, rva_rip, 1, &insn);
        if (count == 0) {
            throw std::runtime_error("Failed to disassemble instruction");
        }
        
        Insn wrapped{*insn};
        
        // Check for JMP/CALL with immediate - use std::array to avoid heap allocation
        bool is_jmp_imm = (insn->id == X86_INS_JMP) && wrapped.is(X86_INS_JMP, std::array{x86_op_type{X86_OP_IMM}});
        bool is_call_imm = (insn->id == X86_INS_CALL) && wrapped.is(X86_INS_CALL, std::array{x86_op_type{X86_OP_IMM}});
        bool is_ret = (insn->id == X86_INS_RET);
        bool is_indirect_jmp = (insn->id == X86_INS_JMP) && !is_jmp_imm;
        
        if (is_call_imm) {
            // Follow call target
            const auto& x86 = insn->detail->x86;
            if (x86.op_count > 0 && x86.operands[0].type == X86_OP_IMM) {
                call_return_stack.push_back(rva_rip + insn->size);
                rva_rip = static_cast<uint32_t>(x86.operands[0].imm);
            }
            // Don't add CALL to stream when inlining
        }
        else if (is_jmp_imm) {
            // Follow unconditional jump, don't add to stream
            const auto& x86 = insn->detail->x86;
            if (x86.op_count > 0 && x86.operands[0].type == X86_OP_IMM) {
                rva_rip = static_cast<uint32_t>(x86.operands[0].imm);
            }
        }
        else if (is_ret) {
            cs_free(insn, count);
            if (!call_return_stack.empty()) {
                rva_rip = static_cast<uint32_t>(call_return_stack.back());
                call_return_stack.pop_back();
                continue;
            }
            break;
        }
        else if (is_indirect_jmp) {
            // Stop at indirect jump or ret
            cs_free(insn, count);
            break;
        }
        else {
            // Add instruction to stream
            output.entries().push_back({++instruction_idx, wrapped});
            rva_rip += insn->size;
        }
        
        cs_free(insn, count);
    }
    
    if (output.empty()) {
        throw std::runtime_error("Failed to unroll control-flow");
    }
    
    return output;
}

void Deobfuscator::invalidate(uint32_t rva) {
    std::unique_lock lock(impl_->mutex);
    impl_->cache.erase(rva);
}

} // namespace vmp::disasm
