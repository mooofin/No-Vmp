#include "subroutines.hpp"
#include "rkey.hpp"
#include <iostream>
#include <map>

namespace vmp {

x86_reg extend_reg(x86_reg r) {
    switch (r) {
        case X86_REG_AL: case X86_REG_AH: case X86_REG_AX: case X86_REG_EAX:
            return X86_REG_RAX;
        case X86_REG_BL: case X86_REG_BH: case X86_REG_BX: case X86_REG_EBX:
            return X86_REG_RBX;
        case X86_REG_CL: case X86_REG_CH: case X86_REG_CX: case X86_REG_ECX:
            return X86_REG_RCX;
        case X86_REG_DL: case X86_REG_DH: case X86_REG_DX: case X86_REG_EDX:
            return X86_REG_RDX;
        case X86_REG_SIL: case X86_REG_SI: case X86_REG_ESI:
            return X86_REG_RSI;
        case X86_REG_DIL: case X86_REG_DI: case X86_REG_EDI:
            return X86_REG_RDI;
        case X86_REG_BPL: case X86_REG_BP: case X86_REG_EBP:
            return X86_REG_RBP;
        case X86_REG_SPL: case X86_REG_SP: case X86_REG_ESP:
            return X86_REG_RSP;
        case X86_REG_R8B: case X86_REG_R8W: case X86_REG_R8D:
            return X86_REG_R8;
        case X86_REG_R9B: case X86_REG_R9W: case X86_REG_R9D:
            return X86_REG_R9;
        case X86_REG_R10B: case X86_REG_R10W: case X86_REG_R10D:
            return X86_REG_R10;
        case X86_REG_R11B: case X86_REG_R11W: case X86_REG_R11D:
            return X86_REG_R11;
        case X86_REG_R12B: case X86_REG_R12W: case X86_REG_R12D:
            return X86_REG_R12;
        case X86_REG_R13B: case X86_REG_R13W: case X86_REG_R13D:
            return X86_REG_R13;
        case X86_REG_R14B: case X86_REG_R14W: case X86_REG_R14D:
            return X86_REG_R14;
        case X86_REG_R15B: case X86_REG_R15W: case X86_REG_R15D:
            return X86_REG_R15;
        default:
            return r;
    }
}

void reduce_chunk(VmState* vstate, disasm::Stream& is, 
    const std::vector<std::pair<RkeyBlock*, RkeyValue>>& parameters, 
    bool has_next) {
    
    // Remove rolling key blocks from the stream in reverse order
    // to maintain index validity
    std::vector<std::pair<int, int>> ranges_to_remove;
    
    for (auto& param_pair : parameters) {
        RkeyBlock* block = param_pair.first;
        if (block && block->block_start.first >= 0 && block->block_end.first >= 0) {
            ranges_to_remove.push_back({block->block_start.first, block->block_end.first + 1});
        }
    }
    
    // Sort ranges by start index in descending order to remove from end first
    std::sort(ranges_to_remove.begin(), ranges_to_remove.end(),
              [](const auto& a, const auto& b) { return a.first > b.first; });
    
    // Remove the ranges
    for (auto& [start, end] : ranges_to_remove) {
        is.erase_range(start, end);
    }
    
    // Handle JA instruction truncation (skip remaining code after conditional jump)
    for (size_t i = 0; i < is.size(); ++i) {
        if (is[i].is(X86_INS_JA, std::vector<x86_op_type>{X86_OP_IMM})) {
            // Truncate at JA - remove everything after the conditional jump
            is.truncate_at(i + 1);
            break;
        }
    }
    
    // Re-normalize after modifications
    is.normalize();
}

void update_vrk(VmState* state, const disasm::Stream& is) {
    // Find XOR with rolling key register writing to stack
    for (size_t i = 0; i < is.size(); ++i) {
        auto ops = is[i].operands();
        if (is[i].is(X86_INS_XOR, std::vector<x86_op_type>{X86_OP_MEM, X86_OP_REG})) {
            if (ops.size() >= 2 &&
                ops[0].mem.base == X86_REG_RSP &&
                ops[0].mem.disp == 0) {
                
                // Look for POP after this XOR
                for (size_t j = i + 1; j < is.size() && j < i + 5; ++j) {
                    auto pop_ops = is[j].operands();
                    if (is[j].is(X86_INS_POP, std::vector<x86_op_type>{X86_OP_REG}) && pop_ops.size() >= 1) {
                        state->reg_vrk = pop_ops[0].reg;
                        return;
                    }
                }
            }
        }
    }
}

void update_vip_direction(VmState* state, const disasm::Stream& is) {
    // Look for forward VIP movement
    auto fwd_filter = [&](const disasm::Insn& ins) -> bool {
        auto ops = ins.operands();
        // ADD reg_vip, 4
        if (ins.is(X86_INS_ADD, std::vector<x86_op_type>{X86_OP_REG, X86_OP_IMM})) {
            if (ops.size() >= 2 && 
                extend_reg(ops[0].reg) == extend_reg(state->reg_vip) &&
                ops[1].imm == 4) {
                return true;
            }
        }
        // LEA reg_vip, [reg_vip+4]
        else if (ins.is(X86_INS_LEA, std::vector<x86_op_type>{X86_OP_REG, X86_OP_MEM})) {
            if (ops.size() >= 2 &&
                ops[0].reg == state->reg_vip &&
                ops[1].mem.disp == 4 &&
                ops[1].mem.scale == 1 &&
                ops[1].mem.base == state->reg_vip) {
                return true;
            }
        }
        return false;
    };
    
    // Look for backward VIP movement
    auto bwd_filter = [&](const disasm::Insn& ins) -> bool {
        auto ops = ins.operands();
        // SUB reg_vip, 4
        if (ins.is(X86_INS_SUB, std::vector<x86_op_type>{X86_OP_REG, X86_OP_IMM})) {
            if (ops.size() >= 2 &&
                extend_reg(ops[0].reg) == extend_reg(state->reg_vip) &&
                ops[1].imm == 4) {
                return true;
            }
        }
        // LEA reg_vip, [reg_vip-4]
        else if (ins.is(X86_INS_LEA, std::vector<x86_op_type>{X86_OP_REG, X86_OP_MEM})) {
            if (ops.size() >= 2 &&
                ops[0].reg == state->reg_vip &&
                ops[1].mem.disp == -4 &&
                ops[1].mem.scale == 1 &&
                ops[1].mem.base == state->reg_vip) {
                return true;
            }
        }
        return false;
    };
    
    int i_fwd = -1, i_bwd = -1;
    for (size_t i = 0; i < is.size(); ++i) {
        if (i_fwd == -1 && fwd_filter(is[i])) i_fwd = i;
        if (i_bwd == -1 && bwd_filter(is[i])) i_bwd = i;
    }
    
    // Determine direction
    if (i_fwd == -1 && i_bwd != -1) {
        state->dir_vip = VipDirection::Backward;
    } else if (i_fwd != -1 && i_bwd == -1) {
        state->dir_vip = VipDirection::Forward;
    } else if (i_fwd != -1 && i_bwd != -1) {
        state->dir_vip = (i_fwd > i_bwd) ? VipDirection::Backward : VipDirection::Forward;
    }
}

std::optional<uint64_t> find_self_ref(VmState*, const disasm::Stream& is, int index) {
    for (size_t i = index; i < is.size(); ++i) {
        auto ops = is[i].operands();
        if (is[i].is(X86_INS_LEA, std::vector<x86_op_type>{X86_OP_REG, X86_OP_MEM})) {
            if (ops.size() >= 2 &&
                ops[1].mem.disp == -7 &&
                ops[1].mem.scale == 1 &&
                ops[1].mem.base == X86_REG_RIP) {
                return is[i].address();
            }
        }
    }
    return std::nullopt;
}

std::pair<std::vector<std::variant<x86_reg, uint64_t>>, uint64_t> 
parse_vmenter(VmState* vstate, uint32_t rva_ep) {
    std::vector<std::variant<x86_reg, uint64_t>> stack;
    
    auto is = vstate->unroll();
    if (is.empty()) return {stack, 0};
    
    // First instruction should be PUSH imm32 (encrypted VIP offset)
    auto ops0 = is[0].operands();
    if (is[0].is(X86_INS_PUSH, std::vector<x86_op_type>{X86_OP_IMM}) && ops0.size() >= 1) {
        stack.push_back(static_cast<uint64_t>(ops0[0].imm));
    }
    
    // Parse stack layout
    for (size_t i = 1; i < is.size(); ++i) {
        auto ops = is[i].operands();
        
        if (is[i].is(X86_INS_PUSH, std::vector<x86_op_type>{X86_OP_REG}) && ops.size() >= 1) {
            stack.push_back(ops[0].reg);
        }
        else if (is[i].is(X86_INS_PUSHFQ, {})) {
            stack.push_back(X86_REG_EFLAGS);
        }
        else if (is[i].is(X86_INS_MOVABS, std::vector<x86_op_type>{X86_OP_REG, X86_OP_IMM})) {
            // End of push sequence
            break;
        }
    }
    
    // Find MOV r64, RSP to identify VSP
    for (size_t i = 0; i < is.size(); ++i) {
        auto ops = is[i].operands();
        if (is[i].is(X86_INS_MOV, std::vector<x86_op_type>{X86_OP_REG, X86_OP_REG})) {
            if (ops.size() >= 2 && ops[1].reg == X86_REG_RSP) {
                // Verify this is the real VSP assignment
                vstate->reg_vsp = ops[0].reg;
                break;
            }
        }
    }
    
    // Find MOV r64, [RSP+offset] to identify VIP
    for (size_t i = 0; i < is.size(); ++i) {
        auto ops = is[i].operands();
        if (is[i].is(X86_INS_MOV, std::vector<x86_op_type>{X86_OP_REG, X86_OP_MEM})) {
            if (ops.size() >= 2 && ops[1].mem.base == X86_REG_RSP) {
                vstate->reg_vip = ops[0].reg;
                break;
            }
        }
    }
    
    // Update VIP direction
    update_vip_direction(vstate, is);
    
    // Update VRK
    update_vrk(vstate, is);
    
    // Calculate initial VIP
    uint64_t initial_vip = rva_ep; // Simplified
    
    return {stack, initial_vip};
}

std::vector<std::variant<x86_reg, uint64_t>> parse_vmexit(VmState*, const disasm::Stream& is) {
    std::vector<std::variant<x86_reg, uint64_t>> stack;
    
    for (size_t i = 0; i < is.size(); ++i) {
        auto ops = is[i].operands();
        
        if (is[i].is(X86_INS_POP, std::vector<x86_op_type>{X86_OP_REG}) && ops.size() >= 1) {
            stack.push_back(ops[0].reg);
        }
        else if (is[i].is(X86_INS_POPFQ, {})) {
            stack.push_back(X86_REG_EFLAGS);
        }
        else if (is[i].is(X86_INS_RET, {})) {
            break;
        }
    }
    
    return stack;
}

std::vector<RkeyBlock> parse_vmswap(VmState* vstate, disasm::Stream& is, disasm::Stream& prefix_out) {
    // Handle register swapping between VM contexts
    if (is.empty()) return {};
    
    auto ops = is[0].operands();
    if (is[0].is(X86_INS_MOV, std::vector<x86_op_type>{X86_OP_REG, X86_OP_MEM})) {
        x86_reg vip_from = ops[0].reg;
        
        // Find mutation end point
        int i_mut_end = -1;
        for (size_t i = 1; i < is.size(); ++i) {
            auto movabs_ops = is[i].operands();
            if (is[i].is(X86_INS_MOVABS, std::vector<x86_op_type>{X86_OP_REG, X86_OP_IMM})) {
                i_mut_end = i;
                break;
            }
        }
        
        if (i_mut_end != -1) {
            // Track register mappings
            std::map<x86_reg, std::pair<int, x86_reg>> register_mappings;
            
            for (int i = 1; i < i_mut_end; ++i) {
                auto insn_ops = is[i].operands();
                if (insn_ops.size() != 2) continue;
                
                if (is[i].is(X86_INS_MOV, std::vector<x86_op_type>{X86_OP_REG, X86_OP_REG})) {
                    x86_reg r1 = insn_ops[0].reg;
                    x86_reg r2 = insn_ops[1].reg;
                    register_mappings[r1] = {i, register_mappings[r2].second};
                }
                else if (is[i].is(X86_INS_XCHG, std::vector<x86_op_type>{X86_OP_REG, X86_OP_REG})) {
                    x86_reg r1 = insn_ops[0].reg;
                    x86_reg r2 = insn_ops[1].reg;
                    std::swap(register_mappings[r1].second, register_mappings[r2].second);
                    register_mappings[r1].first = i;
                    register_mappings[r2].first = i;
                }
            }
            
            // Find inheritance
            auto inherits_from = [&](x86_reg reg) -> std::vector<std::pair<int, x86_reg>> {
                std::vector<std::pair<int, x86_reg>> inheritance;
                for (auto& pair : register_mappings) {
                    if (pair.second.first != 0 && pair.second.second == reg) {
                        inheritance.push_back({pair.second.first, pair.first});
                    }
                }
                std::sort(inheritance.begin(), inheritance.end());
                return inheritance;
            };
            
            auto vip_inh = inherits_from(vip_from);
            auto vsp_inh = inherits_from(vstate->reg_vsp);
            
            if (!vip_inh.empty()) {
                vstate->reg_vip = vip_inh[0].second;
            }
            if (!vsp_inh.empty()) {
                vstate->reg_vsp = vsp_inh.back().second;
            }
            if (vip_inh.size() >= 2) {
                vstate->reg_vrk = vip_inh[1].second;
            }
            
            // Update direction
            update_vip_direction(vstate, is);
        }
    }
    
    // Extract rkey blocks
    return extract_rkey_blocks(vstate, is);
}

} // namespace vmp
