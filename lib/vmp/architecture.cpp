#include "architecture.hpp"
#include "subroutines.hpp"
#include <cstring>

namespace vmp::arch {

char to_char(OpSize s) noexcept {
    switch (s) {
        case OpSize::B: return 'B';
        case OpSize::W: return 'W';
        case OpSize::D: return 'D';
        case OpSize::Q: return 'Q';
    }
    return 'Q';
}

OpSize from_char(char c) {
    switch (c) {
        case 'B': case 'b': return OpSize::B;
        case 'W': case 'w': return OpSize::W;
        case 'D': case 'd': return OpSize::D;
        case 'Q': case 'q': return OpSize::Q;
    }
    throw std::runtime_error("Invalid OpSize char");
}

// Helper: Check if instruction writes to VSP-based memory
static bool i_write_vsp(VmState* vstate, const disasm::Insn& i, uint32_t offset, OpSize variant) {
    auto ops = i.operands();
    if (ops.empty()) return false;
    
    if (ops[0].type != X86_OP_MEM) return false;
    if (ops[0].mem.base != vstate->reg_vsp) return false;
    if (ops[0].mem.index != X86_REG_INVALID) return false;
    if (ops[0].mem.disp != offset) return false;
    
    if (variant == OpSize::B) {
        return i.id() == X86_INS_MOV || i.id() == X86_INS_MOVZX;
    }
    return i.id() == X86_INS_MOV;
}

// Helper: Check if instruction reads from VSP-based memory
static bool i_read_vsp(VmState* vstate, const disasm::Insn& i, uint32_t offset, OpSize variant) {
    auto ops = i.operands();
    if (ops.size() < 2) return false;
    
    if (ops[1].type != X86_OP_MEM) return false;
    if (ops[1].mem.base != vstate->reg_vsp) return false;
    if (ops[1].mem.index != X86_REG_INVALID) return false;
    if (ops[1].mem.disp != offset) return false;
    
    if (variant == OpSize::B) {
        return i.id() == X86_INS_MOV || i.id() == X86_INS_MOVZX;
    }
    return i.id() == X86_INS_MOV;
}

// Helper: Check if instruction shifts VSP
static bool i_shift_vsp(VmState* vstate, const disasm::Insn& i, int32_t offset) {
    auto ops = i.operands();
    if (ops.size() < 2) return false;
    
    if (ops[0].type != X86_OP_REG) return false;
    if (extend_reg(ops[0].reg) != extend_reg(vstate->reg_vsp)) return false;
    if (ops[1].type != X86_OP_IMM) return false;
    
    if (offset > 0) {
        return i.id() == X86_INS_ADD && ops[1].imm == offset;
    } else {
        return i.id() == X86_INS_SUB && ops[1].imm == -offset;
    }
}

// Helper: Check for load constant
static bool i_loadc(const disasm::Insn& i) {
    return std::strcmp(i.raw.mnemonic, "loadc") == 0;
}

// Extract parameter size from instruction
static OpSize get_param_size(const disasm::Insn& i) {
    auto ops = i.operands();
    if (ops.empty()) return OpSize::Q;
    
    for (const auto& op : ops) {
        if (op.size != 0) {
            switch (op.size) {
                case 1: return OpSize::B;
                case 2: return OpSize::W;
                case 4: return OpSize::D;
                case 8: return OpSize::Q;
            }
        }
    }
    return OpSize::Q;
}

Instruction classify(VmState* vstate, const disasm::Stream& stream) {
    Instruction ins;
    ins.handler_stream = stream;
    ins.op = "VUNK"; // Default to unknown
    
    if (stream.empty()) return ins;
    
    // Extract parameters from loadc instructions
    for (size_t i = 0; i < stream.size(); ++i) {
        if (i_loadc(stream[i])) {
            auto ops = stream[i].operands();
            if (ops.size() >= 2 && ops[1].type == X86_OP_IMM) {
                ins.params.push_back(ops[1].imm);
                ins.param_sizes.push_back(get_param_size(stream[i]));
            }
        }
    }
    
    // Analyze stack operations and determine opcode type
    int32_t current_offset = 0;
    bool has_vsp_write = false;
    bool has_vsp_read = false;
    bool has_loadc = !ins.params.empty();
    
    for (size_t i = 0; i < stream.size(); ++i) {
        const auto& insn = stream[i];
        
        // Check for VSP writes (VPUSH)
        for (size_t sz = 1; sz <= 8; sz *= 2) {
            OpSize variant = (sz == 1) ? OpSize::B : (sz == 2) ? OpSize::W : (sz == 4) ? OpSize::D : OpSize::Q;
            if (i_write_vsp(vstate, insn, current_offset, variant)) {
                ins.stack_writes.insert(current_offset);
                ins.stack_delta -= sz;
                current_offset += sz;
                has_vsp_write = true;
                break;
            }
        }
        
        // Check for VSP reads (VPOP)
        for (size_t sz = 1; sz <= 8; sz *= 2) {
            OpSize variant = (sz == 1) ? OpSize::B : (sz == 2) ? OpSize::W : (sz == 4) ? OpSize::D : OpSize::Q;
            if (i_read_vsp(vstate, insn, current_offset, variant)) {
                ins.stack_reads.insert(current_offset);
                ins.stack_delta += sz;
                current_offset -= sz;
                has_vsp_read = true;
                break;
            }
        }
        
        // Check for VSP shifts
        if (insn.id() == X86_INS_ADD || insn.id() == X86_INS_SUB) {
            auto ops = insn.operands();
            if (ops.size() >= 2 && 
                ops[0].type == X86_OP_REG && 
                extend_reg(ops[0].reg) == extend_reg(vstate->reg_vsp) &&
                ops[1].type == X86_OP_IMM) {
                int32_t shift = (insn.id() == X86_INS_ADD) ? ops[1].imm : -ops[1].imm;
                ins.stack_delta += shift;
                current_offset += shift;
            }
        }
        
        // Check for arithmetic operations
        switch (insn.id()) {
            case X86_INS_ADD:
                if (ins.op == "VUNK") ins.op = "VADD";
                break;
            case X86_INS_SUB:
                if (ins.op == "VUNK") ins.op = "VSUB";
                break;
            case X86_INS_AND:
                if (ins.op == "VUNK") ins.op = "VAND";
                break;
            case X86_INS_OR:
                if (ins.op == "VUNK") ins.op = "VOR";
                break;
            case X86_INS_XOR:
                if (ins.op == "VUNK") ins.op = "VXOR";
                break;
            case X86_INS_SHR:
                if (ins.op == "VUNK") ins.op = "VSHR";
                break;
            case X86_INS_SHL:
                if (ins.op == "VUNK") ins.op = "VSHL";
                break;
            case X86_INS_NEG:
                if (ins.op == "VUNK") ins.op = "VNEG";
                break;
            case X86_INS_NOT:
                if (ins.op == "VUNK") ins.op = "VNOT";
                break;
            case X86_INS_CMP:
                if (ins.op == "VUNK") ins.op = "VCMP";
                break;
            case X86_INS_JMP:
                if (ins.op == "VUNK") ins.op = "VJMP";
                break;
            case X86_INS_RET:
                if (ins.op == "VUNK") ins.op = "VRET";
                break;
        }
    }
    
    // Determine if this is a stack operation (VPUSH/VPOP) when no arithmetic op found
    if (ins.op == "VUNK") {
        if (has_vsp_write && !has_vsp_read) {
            // Only writes to VSP - this is a VPUSH
            // Determine if pushing constant or register based on parameters
            if (has_loadc && !ins.params.empty()) {
                ins.op = "VPUSHC";
            } else {
                ins.op = "VPUSHV";
            }
        } else if (has_vsp_read && !has_vsp_write) {
            // Only reads from VSP - this is a VPOP
            if (ins.ctx_writes.empty()) {
                ins.op = "VPOPD";  // Pop and discard
            } else {
                ins.op = "VPOPV";  // Pop into virtual register
            }
        }
    }
    
    // Add unsigned suffix and size suffix to opcode
    // Operations that set flags get 'U' suffix
    bool is_unsigned_op = ins.op == "VADD" || ins.op == "VSUB" || ins.op == "VAND" || 
                          ins.op == "VOR" || ins.op == "VXOR" || ins.op == "VSHR" || 
                          ins.op == "VSHL" || ins.op == "VNOR" || ins.op == "VNAND" ||
                          ins.op == "VCMP";
    
    if (is_unsigned_op) {
        ins.op += 'U';
    }
    
    if (!ins.param_sizes.empty()) {
        ins.op += to_char(ins.param_sizes[0]);
    } else {
        ins.op += 'Q';
    }
    
    return ins;
}

} // namespace vmp::arch
