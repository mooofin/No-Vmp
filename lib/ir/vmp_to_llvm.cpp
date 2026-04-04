#include "vmp_to_llvm.hpp"
#include "../vmp/subroutines.hpp"
#include "../vmp/rkey.hpp"
#include <iostream>
#include <unordered_map>
#include <llvm/IR/InlineAsm.h>

namespace vmp::ir {

// Helper to get integer type for a given size in bits
static llvm::IntegerType* getIntTy(llvm::LLVMContext& ctx, unsigned bits) {
    return llvm::IntegerType::get(ctx, bits);
}

// Helper to create a constant int
static llvm::ConstantInt* getConstInt(llvm::LLVMContext& ctx, uint64_t val, unsigned bits = 64) {
    return llvm::ConstantInt::get(getIntTy(ctx, bits), val);
}

// Helper to load from VSP
static llvm::Value* loadFromVSP(llvm::IRBuilder<>& builder, llvm::Value* vspPtr, 
                                 unsigned sizeBits, llvm::LLVMContext& ctx) {
    llvm::Type* intTy = getIntTy(ctx, sizeBits);
    llvm::Value* vspVal = builder.CreateLoad(builder.getInt64Ty(), vspPtr, "vsp");
    llvm::Value* ptr = builder.CreateIntToPtr(vspVal, llvm::PointerType::get(intTy, 0));
    return builder.CreateLoad(intTy, ptr, "load_vsp");
}

// Helper to store to VSP
static void storeToVSP(llvm::IRBuilder<>& builder, llvm::Value* vspPtr, 
                       llvm::Value* val, llvm::LLVMContext& ctx) {
    llvm::Value* vspVal = builder.CreateLoad(builder.getInt64Ty(), vspPtr, "vsp");
    llvm::Type* valTy = val->getType();
    llvm::Value* ptr = builder.CreateIntToPtr(vspVal, llvm::PointerType::get(valTy, 0));
    builder.CreateStore(val, ptr);
}

// Helper to adjust VSP
static void adjustVSP(llvm::IRBuilder<>& builder, llvm::Value* vspPtr, 
                      int32_t delta, llvm::LLVMContext& ctx) {
    llvm::Value* vspVal = builder.CreateLoad(builder.getInt64Ty(), vspPtr, "vsp");
    llvm::Value* newVsp = builder.CreateAdd(vspVal, getConstInt(ctx, delta), "vsp_adj");
    builder.CreateStore(newVsp, vspPtr);
}

// Helper to pop from stack (load then adjust VSP)
static llvm::Value* popFromStack(llvm::IRBuilder<>& builder, llvm::Value* vspPtr,
                                  unsigned sizeBits, llvm::LLVMContext& ctx) {
    llvm::Value* val = loadFromVSP(builder, vspPtr, sizeBits, ctx);
    adjustVSP(builder, vspPtr, sizeBits / 8, ctx);
    return val;
}

// Helper to push to stack (adjust VSP then store)
static void pushToStack(llvm::IRBuilder<>& builder, llvm::Value* vspPtr,
                         llvm::Value* val, llvm::LLVMContext& ctx) {
    unsigned sizeBits = val->getType()->getIntegerBitWidth();
    adjustVSP(builder, vspPtr, -(int32_t)(sizeBits / 8), ctx);
    storeToVSP(builder, vspPtr, val, ctx);
}

// Helper to compute EFLAGS
static llvm::Value* computeFlags(llvm::IRBuilder<>& builder, llvm::Value* result,
                                  llvm::Value* lhs, llvm::Value* rhs, bool isSub,
                                  llvm::LLVMContext& ctx) {
    unsigned bits = result->getType()->getIntegerBitWidth();
    llvm::Type* i64Ty = builder.getInt64Ty();
    
    // CF (bit 0): Carry flag - for add: result < lhs, for sub: result > lhs
    llvm::Value* cf;
    if (isSub) {
        cf = builder.CreateICmpUGT(result, lhs, "cf_cmp");
    } else {
        cf = builder.CreateICmpULT(result, lhs, "cf_cmp");
    }
    cf = builder.CreateZExt(cf, i64Ty);
    
    // SF (bit 7): Sign flag - sign bit of result
    llvm::Value* signBit = builder.CreateLShr(result, bits - 1, "sign_bit");
    llvm::Value* sf = builder.CreateAnd(signBit, 1, "sf");
    sf = builder.CreateZExt(sf, i64Ty);
    
    // ZF (bit 6): Zero flag - result == 0
    llvm::Value* zf = builder.CreateICmpEQ(result, llvm::ConstantInt::get(result->getType(), 0), "zf_cmp");
    zf = builder.CreateZExt(zf, i64Ty);
    zf = builder.CreateShl(zf, 6, "zf_shl");
    
    // OF (bit 11): Overflow flag - signed overflow
    // For add: (lhs_sign == rhs_sign) && (lhs_sign != result_sign)
    llvm::Value* lhsSign = builder.CreateLShr(lhs, bits - 1);
    llvm::Value* rhsSign = builder.CreateLShr(rhs, bits - 1);
    llvm::Value* resSign = builder.CreateLShr(result, bits - 1);
    
    llvm::Value* sameSign = builder.CreateICmpEQ(lhsSign, rhsSign);
    llvm::Value* diffResSign = builder.CreateICmpNE(lhsSign, resSign);
    llvm::Value* of = builder.CreateAnd(sameSign, diffResSign, "of");
    of = builder.CreateZExt(of, i64Ty);
    of = builder.CreateShl(of, 11, "of_shl");
    
    // Combine: CF | ZF | SF | OF (PF and AF omitted for simplicity)
    llvm::Value* flags = builder.CreateOr(cf, zf, "flags_zf");
    flags = builder.CreateOr(flags, sf, "flags_sf");
    flags = builder.CreateOr(flags, of, "flags_of");
    
    return flags;
}

// Main translate function
llvm::BasicBlock* translate(LiftContext& lctx, llvm::BasicBlock* bb, 
                            const arch::Instruction& insn, llvm::Value** jumpTarget) {
    llvm::IRBuilder<> builder(bb);
    auto& ctx = lctx.ctx();
    llvm::Value* vspPtr = lctx.get_vsp();
    llvm::Value* flagsPtr = lctx.get_flags();
    
    // Extract size from opcode suffix
    auto getSize = [](const std::string& op) -> unsigned {
        if (op.back() == 'B') return 8;
        if (op.back() == 'W') return 16;
        if (op.back() == 'D') return 32;
        if (op.back() == 'Q') return 64;
        return 64;
    };
    
    unsigned bits = getSize(insn.op);
    llvm::Type* intTy = getIntTy(ctx, bits);
    llvm::Type* i64Ty = builder.getInt64Ty();
    
    // VPOPV* - pop into virtual register
    if (insn.op.find("VPOPV") == 0) {
        llvm::Value* val = popFromStack(builder, vspPtr, bits, ctx);
        if (!insn.params.empty()) {
            llvm::AllocaInst* vreg = lctx.get_vreg(insn.params[0], bits);
            builder.CreateStore(val, vreg);
        }
    }
    // VPOPD* - pop and discard
    else if (insn.op.find("VPOPD") == 0) {
        adjustVSP(builder, vspPtr, bits / 8, ctx);
    }
    // VPUSHC* - push constant
    else if (insn.op.find("VPUSHC") == 0) {
        uint64_t val = insn.params.empty() ? 0 : insn.params[0];
        llvm::Value* constVal = llvm::ConstantInt::get(intTy, val);
        pushToStack(builder, vspPtr, constVal, ctx);
    }
    // VPUSHV* - push virtual register
    else if (insn.op.find("VPUSHV") == 0) {
        if (!insn.params.empty()) {
            llvm::AllocaInst* vreg = lctx.get_vreg(insn.params[0], bits);
            llvm::Value* val = builder.CreateLoad(intTy, vreg, "vreg_load");
            pushToStack(builder, vspPtr, val, ctx);
        }
    }
    // VPUSHR* - push saved VSP
    else if (insn.op.find("VPUSHR") == 0) {
        llvm::Value* savedVsp = builder.CreateLoad(i64Ty, vspPtr, "saved_vsp");
        llvm::Value* savedVspInt = builder.CreateTruncOrBitCast(savedVsp, intTy);
        pushToStack(builder, vspPtr, savedVspInt, ctx);
    }
    // VADDU* - add with flags
    else if (insn.op.find("VADDU") == 0) {
        llvm::Value* rhs = popFromStack(builder, vspPtr, bits, ctx);
        llvm::Value* lhs = popFromStack(builder, vspPtr, bits, ctx);
        llvm::Value* result = builder.CreateAdd(lhs, rhs, "add");
        llvm::Value* flags = computeFlags(builder, result, lhs, rhs, false, ctx);
        pushToStack(builder, vspPtr, result, ctx);
        builder.CreateStore(flags, flagsPtr);
    }
    // VSUBU* - sub with flags (similar to add)
    else if (insn.op.find("VSUBU") == 0) {
        llvm::Value* rhs = popFromStack(builder, vspPtr, bits, ctx);
        llvm::Value* lhs = popFromStack(builder, vspPtr, bits, ctx);
        llvm::Value* result = builder.CreateSub(lhs, rhs, "sub");
        llvm::Value* flags = computeFlags(builder, result, lhs, rhs, true, ctx);
        pushToStack(builder, vspPtr, result, ctx);
        builder.CreateStore(flags, flagsPtr);
    }
    // VNORU* - NOR operation: NOT(a) OR NOT(b)
    else if (insn.op.find("VNORU") == 0) {
        llvm::Value* b = popFromStack(builder, vspPtr, bits, ctx);
        llvm::Value* a = popFromStack(builder, vspPtr, bits, ctx);
        llvm::Value* notA = builder.CreateNot(a, "not_a");
        llvm::Value* notB = builder.CreateNot(b, "not_b");
        llvm::Value* result = builder.CreateOr(notA, notB, "nor");
        llvm::Value* flags = computeFlags(builder, result, a, b, false, ctx);
        pushToStack(builder, vspPtr, result, ctx);
        builder.CreateStore(flags, flagsPtr);
    }
    // VNANDU* - NAND operation: NOT(a) AND NOT(b)
    else if (insn.op.find("VNANDU") == 0) {
        llvm::Value* b = popFromStack(builder, vspPtr, bits, ctx);
        llvm::Value* a = popFromStack(builder, vspPtr, bits, ctx);
        llvm::Value* notA = builder.CreateNot(a, "not_a");
        llvm::Value* notB = builder.CreateNot(b, "not_b");
        llvm::Value* result = builder.CreateAnd(notA, notB, "nand");
        llvm::Value* flags = computeFlags(builder, result, a, b, false, ctx);
        pushToStack(builder, vspPtr, result, ctx);
        builder.CreateStore(flags, flagsPtr);
    }
    // VANDU* - AND with flags
    else if (insn.op.find("VANDU") == 0) {
        llvm::Value* rhs = popFromStack(builder, vspPtr, bits, ctx);
        llvm::Value* lhs = popFromStack(builder, vspPtr, bits, ctx);
        llvm::Value* result = builder.CreateAnd(lhs, rhs, "and");
        llvm::Value* flags = computeFlags(builder, result, lhs, rhs, false, ctx);
        pushToStack(builder, vspPtr, result, ctx);
        builder.CreateStore(flags, flagsPtr);
    }
    // VORU* - OR with flags
    else if (insn.op.find("VORU") == 0) {
        llvm::Value* rhs = popFromStack(builder, vspPtr, bits, ctx);
        llvm::Value* lhs = popFromStack(builder, vspPtr, bits, ctx);
        llvm::Value* result = builder.CreateOr(lhs, rhs, "or");
        llvm::Value* flags = computeFlags(builder, result, lhs, rhs, false, ctx);
        pushToStack(builder, vspPtr, result, ctx);
        builder.CreateStore(flags, flagsPtr);
    }
    // VXORU* - XOR with flags
    else if (insn.op.find("VXORU") == 0) {
        llvm::Value* rhs = popFromStack(builder, vspPtr, bits, ctx);
        llvm::Value* lhs = popFromStack(builder, vspPtr, bits, ctx);
        llvm::Value* result = builder.CreateXor(lhs, rhs, "xor");
        llvm::Value* flags = computeFlags(builder, result, lhs, rhs, false, ctx);
        pushToStack(builder, vspPtr, result, ctx);
        builder.CreateStore(flags, flagsPtr);
    }
    // VSHRU* - logical shift right
    else if (insn.op.find("VSHRU") == 0) {
        llvm::Value* shiftCount = popFromStack(builder, vspPtr, 16, ctx);
        llvm::Value* val = popFromStack(builder, vspPtr, bits, ctx);
        llvm::Value* result = builder.CreateLShr(val, shiftCount, "lshr");
        llvm::Value* flags = computeFlags(builder, result, val, shiftCount, false, ctx);
        pushToStack(builder, vspPtr, result, ctx);
        builder.CreateStore(flags, flagsPtr);
    }
    // VSHLU* - shift left
    else if (insn.op.find("VSHLU") == 0) {
        llvm::Value* shiftCount = popFromStack(builder, vspPtr, 16, ctx);
        llvm::Value* val = popFromStack(builder, vspPtr, bits, ctx);
        llvm::Value* result = builder.CreateShl(val, shiftCount, "shl");
        llvm::Value* flags = computeFlags(builder, result, val, shiftCount, false, ctx);
        pushToStack(builder, vspPtr, result, ctx);
        builder.CreateStore(flags, flagsPtr);
    }
    // VNEG* - negate
    else if (insn.op.find("VNEG") == 0) {
        llvm::Value* val = popFromStack(builder, vspPtr, bits, ctx);
        llvm::Value* result = builder.CreateNeg(val, "neg");
        llvm::Value* flags = computeFlags(builder, result, val, val, true, ctx);
        pushToStack(builder, vspPtr, result, ctx);
        builder.CreateStore(flags, flagsPtr);
    }
    // VNOT* - bitwise NOT
    else if (insn.op.find("VNOT") == 0) {
        llvm::Value* val = popFromStack(builder, vspPtr, bits, ctx);
        llvm::Value* result = builder.CreateNot(val, "not");
        pushToStack(builder, vspPtr, result, ctx);
    }
    // VREADU* - read from memory
    else if (insn.op.find("VREADU") == 0) {
        llvm::Value* ptrVal = popFromStack(builder, vspPtr, 64, ctx);
        llvm::Type* ptrTy = llvm::PointerType::get(intTy, 0);
        llvm::Value* ptr = builder.CreateIntToPtr(ptrVal, ptrTy, "read_ptr");
        llvm::Value* val = builder.CreateLoad(intTy, ptr, "read_val");
        pushToStack(builder, vspPtr, val, ctx);
    }
    // VWRITEU* - write to memory
    else if (insn.op.find("VWRITEU") == 0) {
        llvm::Value* ptrVal = popFromStack(builder, vspPtr, 64, ctx);
        llvm::Value* val = popFromStack(builder, vspPtr, bits, ctx);
        llvm::Type* ptrTy = llvm::PointerType::get(intTy, 0);
        llvm::Value* ptr = builder.CreateIntToPtr(ptrVal, ptrTy, "write_ptr");
        builder.CreateStore(val, ptr);
        adjustVSP(builder, vspPtr, 8 + bits/8, ctx);
    }
    // VSETVSP - set VSP from stack
    else if (insn.op.find("VSETVSP") == 0) {
        llvm::Value* newVsp = popFromStack(builder, vspPtr, 64, ctx);
        builder.CreateStore(newVsp, vspPtr);
    }
    // VJMP / VJCC - jump
    else if (insn.op.find("VJMP") == 0 || insn.op.find("VJCC") == 0) {
        llvm::Value* target = popFromStack(builder, vspPtr, 64, ctx);
        if (jumpTarget) *jumpTarget = target;
        // Return without terminating block - let lift_routine handle it
        return bb;
    }
    // VRET / VMEXIT - return from VM
    else if (insn.op.find("VRET") == 0 || insn.op.find("VMEXIT") == 0) {
        builder.CreateRetVoid();
        return bb;
    }
    // VNOP - no operation
    else if (insn.op.find("VNOP") == 0) {
        // Emit nothing
    }
    // VCPUID - CPUID instruction
    else if (insn.op.find("VCPUID") == 0) {
        llvm::Value* leaf = popFromStack(builder, vspPtr, 64, ctx);
        
        // Emit inline asm: cpuid
        llvm::FunctionType* asmTy = llvm::FunctionType::get(
            builder.getVoidTy(),
            {builder.getInt32Ty()}, false);
        llvm::InlineAsm* cpuidAsm = llvm::InlineAsm::get(
            asmTy,
            "cpuid",
            "=a,=b,=c,=d,a",
            true); // hasSideEffects
        
        llvm::Value* eax = builder.CreateCall(cpuidAsm, {builder.CreateTrunc(leaf, builder.getInt32Ty())});
        
        // Push results in order: EDX, ECX, EBX, EAX
        // (Need to extract from asm results - simplified version)
        llvm::Value* results[4] = {
            builder.getInt32(0), // EDX placeholder
            builder.getInt32(0), // ECX placeholder  
            builder.getInt32(0), // EBX placeholder
            builder.getInt32(0)  // EAX placeholder
        };
        
        for (int i = 0; i < 4; ++i) {
            adjustVSP(builder, vspPtr, -4, ctx);
            llvm::Value* ptr = builder.CreateIntToPtr(
                builder.CreateLoad(i64Ty, vspPtr),
                llvm::PointerType::get(builder.getInt32Ty(), 0));
            builder.CreateStore(results[i], ptr);
        }
    }
    // VRDTSC - read timestamp counter
    else if (insn.op.find("VRDTSC") == 0) {
        llvm::FunctionType* asmTy = llvm::FunctionType::get(
            llvm::StructType::get(builder.getInt32Ty(), builder.getInt32Ty()),
            {}, false);
        llvm::InlineAsm* rdtscAsm = llvm::InlineAsm::get(
            asmTy, "rdtsc", "=a,=d", true);
        
        llvm::Value* result = builder.CreateCall(rdtscAsm);
        llvm::Value* eax = builder.CreateExtractValue(result, 0);
        llvm::Value* edx = builder.CreateExtractValue(result, 1);
        
        // Push EDX then EAX
        adjustVSP(builder, vspPtr, -4, ctx);
        llvm::Value* edxPtr = builder.CreateIntToPtr(
            builder.CreateLoad(i64Ty, vspPtr),
            llvm::PointerType::get(builder.getInt32Ty(), 0));
        builder.CreateStore(edx, edxPtr);
        
        adjustVSP(builder, vspPtr, -4, ctx);
        llvm::Value* eaxPtr = builder.CreateIntToPtr(
            builder.CreateLoad(i64Ty, vspPtr),
            llvm::PointerType::get(builder.getInt32Ty(), 0));
        builder.CreateStore(eax, eaxPtr);
    }
    // VPUSHCR0 / VPUSHCR3 - read control registers
    else if (insn.op.find("VPUSHCR0") == 0 || insn.op.find("VPUSHCR3") == 0) {
        bool isCr0 = (insn.op.find("VPUSHCR0") == 0);
        std::string asmStr = isCr0 ? "mov %cr0, $0" : "mov %cr3, $0";
        
        llvm::FunctionType* asmTy = llvm::FunctionType::get(builder.getInt64Ty(), {}, false);
        llvm::InlineAsm* crAsm = llvm::InlineAsm::get(asmTy, asmStr, "=r", true);
        llvm::Value* val = builder.CreateCall(crAsm);
        
        adjustVSP(builder, vspPtr, -8, ctx);
        storeToVSP(builder, vspPtr, val, ctx);
    }
    // VEMIT / VEXEC - emit raw handler bytes as inline asm
    else if (insn.op.find("VEMIT") == 0 || insn.op.find("VEXEC") == 0) {
        auto bytes = insn.handler_stream.to_bytes();
        if (!bytes.empty()) {
            // Convert bytes to asm string
            std::string asmStr;
            for (auto b : bytes) {
                asmStr += ".byte 0x" + std::to_string(b) + "\n";
            }
            
            llvm::FunctionType* asmTy = llvm::FunctionType::get(builder.getVoidTy(), {}, false);
            llvm::InlineAsm* rawAsm = llvm::InlineAsm::get(asmTy, asmStr, "", true);
            builder.CreateCall(rawAsm);
        }
    }
    // VUNK - unknown
    else {
        std::cerr << "Warning: Unhandled VMP opcode: " << insn.op << std::endl;
        builder.CreateUnreachable();
    }
    
    return bb;
}

// Full routine lifter
std::unique_ptr<LiftContext> lift_routine(VmState& state) {
    char name_buf[64];
    std::snprintf(name_buf, sizeof(name_buf), "vmp_%08x", state.handler_rva);
    
    auto lctx = std::make_unique<LiftContext>(
        std::string(name_buf),
        state.img->image_base());
    
    llvm::LLVMContext& ctx = lctx->ctx();
    llvm::IRBuilder<> builder(ctx);
    
    // Map to track explored blocks by VIP
    std::unordered_map<uint64_t, llvm::BasicBlock*> exploredBlocks;
    
    // Parse VMENTER to initialize
    auto [stack, entryVip] = parse_vmenter(&state, state.handler_rva);
    
    // Initialize VSP (set to initial stack position)
    // TODO: Calculate proper initial VSP from parse_vmenter results
    
    // Main lifting loop
    std::vector<uint64_t> workList = {entryVip};
    while (!workList.empty()) {
        uint64_t currentVip = workList.back();
        workList.pop_back();
        
        // Skip if already explored
        if (exploredBlocks.count(currentVip)) continue;
        
        // Create basic block for this VIP
        llvm::BasicBlock* bb = llvm::BasicBlock::Create(ctx, "", lctx->fn());
        exploredBlocks[currentVip] = bb;
        builder.SetInsertPoint(bb);
        
        // Set current VIP in state
        state.vip = currentVip;
        
        // Unroll handler stream
        auto stream = state.unroll();
        if (stream.empty()) {
            builder.CreateUnreachable();
            continue;
        }
        
        // Extract rolling key blocks
        auto rkeyBlocks = extract_rkey_blocks(&state, stream);
        
        // Check for self-reference (branching/VMENTER)
        auto selfRef = find_self_ref(&state, stream, 0);
        if (selfRef) {
            // Handle VM chaining or branching
            // TODO: Implement parse_vmswap for register mutation
            // For now, treat as VMEXIT
            builder.CreateRetVoid();
            continue;
        }
        
        // Reduce chunk (remove decryption blocks)
        disasm::Stream reduced = stream;
        // TODO: Call reduce_chunk properly with extracted parameters
        
        // Classify instruction
        auto insn = arch::classify(&state, reduced);
        
        // Translate to LLVM IR
        llvm::Value* jumpTarget = nullptr;
        llvm::BasicBlock* nextBb = translate(*lctx, bb, insn, &jumpTarget);
        
        // Handle jump target
        if (jumpTarget) {
            // Indirect or direct jump - resolve target
            // TODO: Evaluate jumpTarget constant, add to workList if new
        }
        
        // Advance to next handler
        if (rkeyBlocks.empty()) {
            // Serial instruction
            // TODO: Extract delta from classification and call state.advance
        } else {
            // Branching instruction with rolling key
            // TODO: Call state.advance with rkeyBlocks.back()
        }
    }
    
    return lctx;
}

} // namespace vmp::ir
