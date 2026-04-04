#include "rkey.hpp"
#include <cstring>

namespace vmp {

std::pair<int, RkeyBlock> extract_next_rkey_block(VmState* state,
                                                   const disasm::Stream& is,
                                                   int index) {
    RkeyBlock out;
    
    // Extend the rolling key register to 64-bit
    out.rolling_key_reg = extend_reg(state->reg_vrk);
    
    // Prologue filter: XOR reg, rolling_key_reg
    auto prologue_filter = [&out](const disasm::Insn& ins) {
        if (ins.is(X86_INS_XOR, std::vector<x86_op_type>{X86_OP_REG, X86_OP_REG})) {
            auto ops = ins.operands();
            if (ops.size() >= 2 && extend_reg(ops[1].reg) == out.rolling_key_reg) {
                return true;
            }
        }
        return false;
    };
    
    // Epilogue filter
    auto epilogue_filter = [&out](const disasm::Insn& ins) {
        // Type #1: XOR rolling_key_reg, output_reg
        if (ins.is(X86_INS_XOR, std::vector<x86_op_type>{X86_OP_REG, X86_OP_REG})) {
            auto ops = ins.operands();
            if (ops.size() >= 2 && 
                extend_reg(ops[0].reg) == out.rolling_key_reg &&
                ops[1].reg == out.output_reg) {
                return true;
            }
        }
        // Type #2: XOR [RSP], output_reg (stack-based)
        else if (ins.is(X86_INS_XOR, std::vector<x86_op_type>{X86_OP_MEM, X86_OP_REG})) {
            auto ops = ins.operands();
            if (ops.size() >= 2 &&
                ops[0].mem.base == X86_REG_RSP &&
                ops[0].mem.disp == 0 &&
                ops[0].mem.index == X86_REG_INVALID &&
                ops[0].mem.scale == 1 &&
                ops[1].reg == out.output_reg) {
                return true;
            }
        }
        return false;
    };
    
    // Find prologue
    int prologue_index = is.find_next(prologue_filter, index);
    if (prologue_index == -1) {
        RkeyBlock empty_block;
        return std::make_pair(-1, empty_block);
    }
    
    // Fill block details
    auto ops = is[prologue_index].operands();
    out.block_start = {prologue_index, is[prologue_index].address()};
    out.output_size = ops[0].size;
    out.output_reg = ops[0].reg;
    
    // Find epilogue
    int epilogue_index = is.find_next(epilogue_filter, prologue_index + 1);
    if (epilogue_index == -1) {
        // Try next prologue recursively
        return extract_next_rkey_block(state, is, prologue_index + 1);
    }
    
    auto epilogue_ops = is[epilogue_index].operands();
    out.block_end = {epilogue_index, is[epilogue_index].address()};
    
    // Trace register usage
    auto trace_result = vmp::disasm::trace_def(is, out.output_reg, epilogue_index - 1, prologue_index + 1);
    auto& block_stream = trace_result.defs;
    auto& block_deps = trace_result.deps;
    
    // If dependencies exist, try next block
    if (!block_deps.empty()) {
        return extract_next_rkey_block(state, is, prologue_index + 1);
    }
    
    // Create decryption thunk
    out.decrypt = [out, block_stream, state](const void* src, RollingKey key) mutable -> std::pair<RkeyValue, RollingKey> {
        RkeyValue value;
        value.raw = 0;
        value.size = out.output_size;
        std::memcpy(&value.raw, src, value.size);
        
        // Emulate prologue: XOR with key
        switch (value.size) {
            case 1: value.raw = (value.raw & ~0xFFULL) | ((value.raw ^ key) & 0xFF); break;
            case 2: value.raw = (value.raw & ~0xFFFFULL) | ((value.raw ^ key) & 0xFFFF); break;
            case 4: value.raw = (value.raw & ~0xFFFFFFFFULL) | ((value.raw ^ key) & 0xFFFFFFFF); break;
            case 8: value.raw ^= key; break;
        }
        
        // Emulate block stream
        auto raw_bytes = block_stream.to_bytes();
        if (!raw_bytes.empty()) {
            std::vector<uint8_t> exec_stream(raw_bytes.begin(), raw_bytes.end());
            exec_stream.push_back(0xC3); // RET
            
            emulator emu;
            emu.set(state->reg_vrk, key);
            emu.set(out.output_reg, value.raw);
            emu.invoke(exec_stream.data());
            value.raw = emu.get(out.output_reg);
        }
        
        // Emulate epilogue: XOR key with output
        switch (value.size) {
            case 1: key ^= (value.raw & 0xFF); break;
            case 2: key ^= (value.raw & 0xFFFF); break;
            case 4: key ^= (value.raw & 0xFFFFFFFF); break;
            case 8: key ^= value.raw; break;
        }
        
        return {value, key};
    };
    
    return {epilogue_index + 1, out};
}

std::vector<RkeyBlock> extract_rkey_blocks(VmState* vstate,
                                          const disasm::Stream& is) {
    std::vector<RkeyBlock> out;
    int iterator = 0;
    
    while (iterator != -1 && iterator < static_cast<int>(is.size())) {
        auto [it_next, block] = extract_next_rkey_block(vstate, is, iterator);
        
        if (it_next == -1) break;
        
        out.push_back(block);
        iterator = it_next;
    }
    
    return out;
}

} // namespace vmp
