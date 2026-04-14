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
    llvm::Value* ptr = builder.CreateIntToPtr(vspVal, builder.getPtrTy());
    return builder.CreateLoad(intTy, ptr, "load_vsp");
}

// Helper to store to VSP
static void storeToVSP(llvm::IRBuilder<>& builder, llvm::Value* vspPtr, 
                       llvm::Value* val, llvm::LLVMContext& ctx) {
    llvm::Value* vspVal = builder.CreateLoad(builder.getInt64Ty(), vspPtr, "vsp");
    llvm::Value* ptr = builder.CreateIntToPtr(vspVal, builder.getPtrTy());
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
    sf = builder.CreateShl(sf, 7, "sf_shl");
    
    // ZF (bit 6): Zero flag - result == 0
    llvm::Value* zf = builder.CreateICmpEQ(result, llvm::ConstantInt::get(result->getType(), 0), "zf_cmp");
    zf = builder.CreateZExt(zf, i64Ty);
    zf = builder.CreateShl(zf, 6, "zf_shl");
    
    // OF (bit 11): Overflow flag - signed overflow
    // Add: (lhs_sign == rhs_sign) && (lhs_sign != result_sign)
    // Sub: (lhs_sign != rhs_sign) && (lhs_sign != result_sign)
    llvm::Value* lhsSign = builder.CreateLShr(lhs, bits - 1);
    llvm::Value* rhsSign = builder.CreateLShr(rhs, bits - 1);
    llvm::Value* resSign = builder.CreateLShr(result, bits - 1);
    
    llvm::Value* diffResSign = builder.CreateICmpNE(lhsSign, resSign);
    llvm::Value* ofCond = nullptr;
    if (isSub) {
        llvm::Value* diffSign = builder.CreateICmpNE(lhsSign, rhsSign);
        ofCond = builder.CreateAnd(diffSign, diffResSign, "of_sub");
    } else {
        llvm::Value* sameSign = builder.CreateICmpEQ(lhsSign, rhsSign);
        ofCond = builder.CreateAnd(sameSign, diffResSign, "of_add");
    }
    llvm::Value* of = builder.CreateZExt(ofCond, i64Ty);
    of = builder.CreateShl(of, 11, "of_shl");
    
    // Combine: CF | ZF | SF | OF (PF and AF omitted for simplicity)
    llvm::Value* flags = builder.CreateOr(cf, zf, "flags_zf");
    flags = builder.CreateOr(flags, sf, "flags_sf");
    flags = builder.CreateOr(flags, of, "flags_of");
    
    return flags;
}

static llvm::Value* maskShiftCount(llvm::IRBuilder<>& builder,
                                   llvm::Value* shiftCount,
                                   unsigned bits) {
    llvm::Value* count = shiftCount;
    if (count->getType()->getIntegerBitWidth() != bits) {
        count = builder.CreateZExtOrTrunc(count, llvm::IntegerType::get(builder.getContext(), bits),
                                          "shift_count_cast");
    }
    return builder.CreateAnd(
        count,
        llvm::ConstantInt::get(count->getType(), bits - 1),
        "shift_count_mask");
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
    // VMULU* - unsigned multiply with flags
    else if (insn.op.find("VMULU") == 0) {
        llvm::Value* rhs = popFromStack(builder, vspPtr, bits, ctx);
        llvm::Value* lhs = popFromStack(builder, vspPtr, bits, ctx);
        llvm::Value* result = builder.CreateMul(lhs, rhs, "mul");
        llvm::Value* flags = computeFlags(builder, result, lhs, rhs, false, ctx);
        pushToStack(builder, vspPtr, result, ctx);
        builder.CreateStore(flags, flagsPtr);
    }
    // VDIVU* - unsigned divide
    else if (insn.op.find("VDIVU") == 0) {
        llvm::Value* divisor = popFromStack(builder, vspPtr, bits, ctx);
        llvm::Value* dividend = popFromStack(builder, vspPtr, bits, ctx);
        llvm::Value* isZero = builder.CreateICmpEQ(
            divisor, llvm::ConstantInt::get(divisor->getType(), 0), "div_zero_check");

        auto* function = bb->getParent();
        auto* div_bb = llvm::BasicBlock::Create(ctx, "vdiv.do", function);
        auto* zero_bb = llvm::BasicBlock::Create(ctx, "vdiv.zero", function);
        auto* merge_bb = llvm::BasicBlock::Create(ctx, "vdiv.merge", function);
        builder.CreateCondBr(isZero, zero_bb, div_bb);

        llvm::IRBuilder<> div_builder(div_bb);
        llvm::Value* div_result = div_builder.CreateUDiv(dividend, divisor, "udiv");
        div_builder.CreateBr(merge_bb);

        llvm::IRBuilder<> zero_builder(zero_bb);
        llvm::Value* zero_result = llvm::ConstantInt::get(divisor->getType(), 0);
        zero_builder.CreateBr(merge_bb);

        builder.SetInsertPoint(merge_bb);
        auto* result_phi = builder.CreatePHI(divisor->getType(), 2, "vdiv_result");
        result_phi->addIncoming(div_result, div_bb);
        result_phi->addIncoming(zero_result, zero_bb);

        llvm::Value* safeResult = result_phi;
        llvm::Value* flags = computeFlags(builder, safeResult, dividend, divisor, false, ctx);
        pushToStack(builder, vspPtr, safeResult, ctx);
        builder.CreateStore(flags, flagsPtr);
    }
    // VREMU* - unsigned remainder
    else if (insn.op.find("VREMU") == 0) {
        llvm::Value* divisor = popFromStack(builder, vspPtr, bits, ctx);
        llvm::Value* dividend = popFromStack(builder, vspPtr, bits, ctx);
        llvm::Value* isZero = builder.CreateICmpEQ(
            divisor, llvm::ConstantInt::get(divisor->getType(), 0), "rem_zero_check");

        auto* function = bb->getParent();
        auto* rem_bb = llvm::BasicBlock::Create(ctx, "vrem.do", function);
        auto* zero_bb = llvm::BasicBlock::Create(ctx, "vrem.zero", function);
        auto* merge_bb = llvm::BasicBlock::Create(ctx, "vrem.merge", function);
        builder.CreateCondBr(isZero, zero_bb, rem_bb);

        llvm::IRBuilder<> rem_builder(rem_bb);
        llvm::Value* rem_result = rem_builder.CreateURem(dividend, divisor, "urem");
        rem_builder.CreateBr(merge_bb);

        llvm::IRBuilder<> zero_builder(zero_bb);
        llvm::Value* zero_result = llvm::ConstantInt::get(divisor->getType(), 0);
        zero_builder.CreateBr(merge_bb);

        builder.SetInsertPoint(merge_bb);
        auto* result_phi = builder.CreatePHI(divisor->getType(), 2, "vrem_result");
        result_phi->addIncoming(rem_result, rem_bb);
        result_phi->addIncoming(zero_result, zero_bb);

        llvm::Value* safeResult = result_phi;
        llvm::Value* flags = computeFlags(builder, safeResult, dividend, divisor, false, ctx);
        pushToStack(builder, vspPtr, safeResult, ctx);
        builder.CreateStore(flags, flagsPtr);
    }
    // VROLU* - rotate left
    else if (insn.op.find("VROLU") == 0) {
        llvm::Value* shiftCount = popFromStack(builder, vspPtr, 16, ctx);
        llvm::Value* val = popFromStack(builder, vspPtr, bits, ctx);
        shiftCount = maskShiftCount(builder, shiftCount, bits);
        llvm::Value* width = llvm::ConstantInt::get(val->getType(), bits);
        // rol = (val << count) | (val >> (width - count))
        llvm::Value* shl = builder.CreateShl(val, shiftCount, "rol_shl");
        llvm::Value* sub = builder.CreateSub(width, shiftCount, "rol_sub");
        llvm::Value* shr = builder.CreateLShr(val, sub, "rol_shr");
        llvm::Value* result = builder.CreateOr(shl, shr, "rol");
        llvm::Value* flags = computeFlags(builder, result, val, shiftCount, false, ctx);
        pushToStack(builder, vspPtr, result, ctx);
        builder.CreateStore(flags, flagsPtr);
    }
    // VRORU* - rotate right
    else if (insn.op.find("VRORU") == 0) {
        llvm::Value* shiftCount = popFromStack(builder, vspPtr, 16, ctx);
        llvm::Value* val = popFromStack(builder, vspPtr, bits, ctx);
        shiftCount = maskShiftCount(builder, shiftCount, bits);
        llvm::Value* width = llvm::ConstantInt::get(val->getType(), bits);
        // ror = (val >> count) | (val << (width - count))
        llvm::Value* shr = builder.CreateLShr(val, shiftCount, "ror_shr");
        llvm::Value* sub = builder.CreateSub(width, shiftCount, "ror_sub");
        llvm::Value* shl = builder.CreateShl(val, sub, "ror_shl");
        llvm::Value* result = builder.CreateOr(shr, shl, "ror");
        llvm::Value* flags = computeFlags(builder, result, val, shiftCount, false, ctx);
        pushToStack(builder, vspPtr, result, ctx);
        builder.CreateStore(flags, flagsPtr);
    }
    // VBSWAP* - byte swap (bswap instruction)
    else if (insn.op.find("VBSWAP") == 0) {
        llvm::Value* val = popFromStack(builder, vspPtr, bits, ctx);
        llvm::Value* result;
        if (bits == 16) {
            // 16-bit bswap: swap bytes
            llvm::Value* hi = builder.CreateShl(val, 8, "bswap_hi");
            llvm::Value* lo = builder.CreateLShr(val, 8, "bswap_lo");
            result = builder.CreateOr(hi, lo, "bswap16");
        } else if (bits == 32) {
            // Use llvm.bswap intrinsic for 32-bit
            llvm::Type* types[] = {intTy};
            llvm::Function* bswap = llvm::Intrinsic::getOrInsertDeclaration(&lctx.module(), llvm::Intrinsic::bswap, llvm::ArrayRef<llvm::Type*>(types, 1));
            result = builder.CreateCall(bswap, {val}, "bswap32");
        } else if (bits == 64) {
            // Use llvm.bswap intrinsic for 64-bit
            llvm::Type* types[] = {intTy};
            llvm::Function* bswap = llvm::Intrinsic::getOrInsertDeclaration(&lctx.module(), llvm::Intrinsic::bswap, llvm::ArrayRef<llvm::Type*>(types, 1));
            result = builder.CreateCall(bswap, {val}, "bswap64");
        } else {
            result = val; // 8-bit: no change
        }
        pushToStack(builder, vspPtr, result, ctx);
    }
    // VREADU* - read from memory
    else if (insn.op.find("VREADU") == 0) {
        llvm::Value* ptrVal = popFromStack(builder, vspPtr, 64, ctx);
        llvm::Value* ptr = builder.CreateIntToPtr(ptrVal, builder.getPtrTy(), "read_ptr");
        llvm::Value* val = builder.CreateLoad(intTy, ptr, "read_val");
        pushToStack(builder, vspPtr, val, ctx);
    }
    // VWRITEU* - write to memory
    else if (insn.op.find("VWRITEU") == 0) {
        llvm::Value* ptrVal = popFromStack(builder, vspPtr, 64, ctx);
        llvm::Value* val = popFromStack(builder, vspPtr, bits, ctx);
        llvm::Value* ptr = builder.CreateIntToPtr(ptrVal, builder.getPtrTy(), "write_ptr");
        builder.CreateStore(val, ptr);
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
    // VCALL - call subroutine (push return address then jump)
    else if (insn.op.find("VCALL") == 0) {
        // VCALL expects at least 2 parameters from VIP stream:
        // params[0]: target address (where to jump)
        // params[1]: return address (where to return after call)
        uint64_t targetAddr = insn.params.size() > 0 ? insn.params[0] : 0;
        uint64_t retAddr = insn.params.size() > 1 ? insn.params[1] : 
                           insn.params.size() > 0 ? insn.params[0] + 8 : 0; // Estimate if not provided
        
        // Pop and discard any runtime-calculated target (VMP may push it first)
        llvm::Value* target = popFromStack(builder, vspPtr, 64, ctx);
        (void)target; // Suppress unused warning - we use the decrypted params instead
        
        // Push return address onto stack
        llvm::Value* retAddrVal = getConstInt(ctx, retAddr, 64);
        pushToStack(builder, vspPtr, retAddrVal, ctx);
        
        // Set jump target from decrypted parameter
        llvm::Value* targetVal = getConstInt(ctx, targetAddr, 64);
        if (jumpTarget) *jumpTarget = targetVal;
        return bb;
    }
    // VLOOP - conditional loop (decrements counter, jumps if not zero)
    else if (insn.op.find("VLOOP") == 0) {
        llvm::Value* target = popFromStack(builder, vspPtr, 64, ctx);
        llvm::Value* counter = popFromStack(builder, vspPtr, bits, ctx);
        llvm::Value* newCounter = builder.CreateSub(counter, llvm::ConstantInt::get(counter->getType(), 1), "loop_dec");
        // The loop condition check would go here - for now just continue to target
        (void)builder.CreateICmpNE(newCounter, llvm::ConstantInt::get(counter->getType(), 0), "loop_test");
        pushToStack(builder, vspPtr, newCounter, ctx);
        // Store condition for potential branch - actual branching handled by lift_routine
        if (jumpTarget) *jumpTarget = target;
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
        llvm::Value* leaf32 = builder.CreateTrunc(leaf, builder.getInt32Ty(), "cpuid_leaf");
        
        // Emit inline asm: cpuid with proper constraints to get all registers
        // Output: EAX, EBX, ECX, EDX
        // Input: EAX (leaf)
        llvm::FunctionType* asmTy = llvm::FunctionType::get(
            llvm::StructType::get(ctx, {builder.getInt32Ty(), builder.getInt32Ty(), builder.getInt32Ty(), builder.getInt32Ty()}),
            {builder.getInt32Ty()}, false);
        llvm::InlineAsm* cpuidAsm = llvm::InlineAsm::get(
            asmTy,
            "cpuid",
            "={ax},={bx},={cx},={dx},{ax}",
            true); // hasSideEffects
        
        llvm::Value* result = builder.CreateCall(cpuidAsm, {leaf32}, "cpuid_result");
        llvm::Value* eax = builder.CreateExtractValue(result, 0, "cpuid_eax");
        llvm::Value* ebx = builder.CreateExtractValue(result, 1, "cpuid_ebx");
        llvm::Value* ecx = builder.CreateExtractValue(result, 2, "cpuid_ecx");
        llvm::Value* edx = builder.CreateExtractValue(result, 3, "cpuid_edx");
        
        // Push results in order: EDX, ECX, EBX, EAX (VMP convention)
        llvm::Value* results[4] = {edx, ecx, ebx, eax};
        
        for (int i = 0; i < 4; ++i) {
            adjustVSP(builder, vspPtr, -4, ctx);
            llvm::Value* vspVal = builder.CreateLoad(i64Ty, vspPtr, "vsp");
            llvm::Value* ptr = builder.CreateIntToPtr(
                vspVal,
                builder.getPtrTy());
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
            builder.getPtrTy());
        builder.CreateStore(edx, edxPtr);
        
        adjustVSP(builder, vspPtr, -4, ctx);
        llvm::Value* eaxPtr = builder.CreateIntToPtr(
            builder.CreateLoad(i64Ty, vspPtr),
            builder.getPtrTy());
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
std::unique_ptr<LiftContext> lift_routine(VmState& state,
                                          size_t& handler_count,
                                          size_t& instructions_before,
                                          size_t& instructions_after) {
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
    
    // Calculate initial VSP based on stack layout from VMENTER
    // Each saved register takes 8 bytes on the stack
    int64_t initial_vsp_offset = static_cast<int64_t>(stack.size() * 8);
    
    // Initialize VSP in LLVM - point to where saved registers end
    llvm::Value* vspPtr = lctx->get_vsp();
    builder.SetInsertPoint(&lctx->fn()->getEntryBlock());
    llvm::Value* initialVsp = llvm::ConstantInt::get(builder.getInt64Ty(), 
        state.img->image_base() + initial_vsp_offset);
    builder.CreateStore(initialVsp, vspPtr);
    
    // Initialize statistics
    handler_count = 0;
    instructions_before = 0;
    instructions_after = 0;
    
    // Main lifting loop
    std::vector<uint64_t> workList = {entryVip};
    while (!workList.empty()) {
        uint64_t currentVip = workList.back();
        workList.pop_back();
        
        // Skip if already explored
        if (exploredBlocks.count(currentVip)) continue;
        
        // Create basic block for this VIP
        llvm::BasicBlock* bb = llvm::BasicBlock::Create(ctx, 
            std::string("vip_") + std::to_string(currentVip), lctx->fn());
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
        
        handler_count++;
        instructions_before += stream.size();
        
        // Extract rolling key blocks
        auto rkeyBlocks = extract_rkey_blocks(&state, stream);
        
        // Check for self-reference (branching/VMENTER)
        auto selfRef = find_self_ref(&state, stream, 0);
        if (selfRef) {
            // Handle VM chaining or branching
            if (state.img->opts.strip_const_obfusc) {
                // Try to parse as VMSWAP for register mutation
                disasm::Stream prefix;
                auto swapBlocks = parse_vmswap(&state, stream, prefix);
                
                // If we have swap blocks, extract parameters from them
                if (!swapBlocks.empty()) {
                    uint64_t new_vip = state.vip;
                    // Advance state
                    state.advance(swapBlocks.back(), new_vip, *selfRef);
                    
                    // Add new VIP to worklist
                    if (!exploredBlocks.count(new_vip)) {
                        workList.push_back(new_vip);
                    }
                    
                    // Create conditional branch based on flags
                    llvm::BasicBlock* true_bb = llvm::BasicBlock::Create(ctx, "", lctx->fn());
                    // For now, create an unconditional branch to continue
                    builder.CreateBr(true_bb);
                    builder.SetInsertPoint(true_bb);
                    
                    instructions_after++;
                    continue;
                }
            }
            
            // Not a swap or couldn't parse - treat as VMEXIT
            builder.CreateRetVoid();
            instructions_after++;
            continue;
        }
        
        // Prepare parameters for reduce_chunk
        std::vector<std::pair<RkeyBlock*, RkeyValue>> parameters;
        for (auto& block : rkeyBlocks) {
            // Decrypt each block's value
            auto value = state.decrypt_vip(const_cast<RkeyBlock&>(block), block.output_size);
            parameters.push_back({const_cast<RkeyBlock*>(&block), value});
        }
        
        // Reduce chunk (remove decryption blocks)
        disasm::Stream reduced = stream;
        bool has_next = true;  // Assume there's a next handler unless proven otherwise
        reduce_chunk(&state, reduced, parameters, has_next);
        
        instructions_after += reduced.size();
        
        // Classify instruction
        auto insn = arch::classify(&state, reduced);
        
        // Translate to LLVM IR
        llvm::Value* jumpTarget = nullptr;
        translate(*lctx, bb, insn, &jumpTarget);
        
        // Handle jump target for VJMP/VJCC
        if (jumpTarget && (insn.op.find("VJMP") == 0 || insn.op.find("VJCC") == 0)) {
            // Try to evaluate jump target constant
            if (llvm::ConstantInt* const_target = llvm::dyn_cast<llvm::ConstantInt>(jumpTarget)) {
                uint64_t target_vip = const_target->getZExtValue();
                
                // Add to worklist if not explored
                if (!exploredBlocks.count(target_vip)) {
                    workList.push_back(target_vip);
                }
                
                // Create branch to the target block (will be resolved later)
                llvm::BasicBlock* target_bb = llvm::BasicBlock::Create(ctx, "", lctx->fn());
                builder.CreateBr(target_bb);
                exploredBlocks[target_vip] = target_bb;
            } else {
                // Indirect jump - can't resolve statically
                // Create switch or indirect branch
                builder.CreateUnreachable();
            }
            continue;
        }
        
        // Handle VMEXIT/VRET
        if (insn.op.find("VMEXIT") == 0 || insn.op.find("VRET") == 0) {
            builder.CreateRetVoid();
            continue;
        }
        
        // Advance to next handler for serial instructions
        if (rkeyBlocks.empty()) {
            // Serial instruction - delta should be in the VIP stream
            // For now, use a default delta of 4 bytes
            RkeyValue delta;
            delta.raw = 4;
            delta.size = 4;
            state.advance(delta);
            
            // Add new VIP to worklist
            if (!exploredBlocks.count(state.vip)) {
                workList.push_back(state.vip);
            }
        } else {
            // Branching instruction - advance using the rolling key block
            if (!parameters.empty()) {
                state.advance(*parameters.back().first, state.vip, state.handler_rva);
                
                // Add new VIP to worklist
                if (!exploredBlocks.count(state.vip)) {
                    workList.push_back(state.vip);
                }
            }
        }
    }
    
    // Populate final basic block for returns if no blocks exist
    if (lctx->fn()->empty()) {
        llvm::BasicBlock* entry = llvm::BasicBlock::Create(ctx, "entry", lctx->fn());
        builder.SetInsertPoint(entry);
        builder.CreateRetVoid();
    }
    
    return lctx;
}

} // namespace vmp::ir
