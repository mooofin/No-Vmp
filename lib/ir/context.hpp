#pragma once
#include <memory>
#include <string>
#include <vector>
#include <unordered_map>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Function.h>

namespace vmp::ir {

// One LLVM context + module pair per lifted routine.
// Each VirtualRoutine gets its own LiftContext so they can be
// optimised and serialised independently.
class LiftContext {
public:
    explicit LiftContext(std::string name, uint64_t image_base);
    ~LiftContext();

    [[nodiscard]] llvm::LLVMContext& ctx()      noexcept { return *ctx_; }
    [[nodiscard]] llvm::Module&      module()   noexcept { return *mod_; }

    // The top-level function being lifted into.
    [[nodiscard]] llvm::Function*    fn()       noexcept { return fn_; }

    // Convenience IRBuilder anchored at the current insertion block.
    [[nodiscard]] llvm::IRBuilder<>& builder()  noexcept { return *builder_; }

    // Helpers for VMP register model.
    // VMP virtual registers → LLVM alloca slots → mem2reg promotes them to SSA.
    [[nodiscard]] llvm::AllocaInst* get_vreg(uint8_t idx, unsigned bits);
    [[nodiscard]] llvm::AllocaInst* get_vsp();   // virtual stack pointer
    [[nodiscard]] llvm::AllocaInst* get_flags();

    // Run mem2reg + DCE + GVN + instcombine on the module.
    void optimize();

    // Serialise to human-readable LLVM IR.
    [[nodiscard]] std::string to_ir_string() const;

    // Serialise to LLVM bitcode bytes.
    [[nodiscard]] std::vector<uint8_t> to_bitcode() const;

private:
    std::unique_ptr<llvm::LLVMContext> ctx_;
    std::unique_ptr<llvm::Module>      mod_;
    std::unique_ptr<llvm::IRBuilder<>> builder_;
    llvm::Function*                    fn_ = nullptr;

    // vreg_idx → alloca
    std::unordered_map<uint32_t, llvm::AllocaInst*> vregs_;
    llvm::AllocaInst* vsp_   = nullptr;
    llvm::AllocaInst* flags_ = nullptr;
};

} // namespace vmp::ir
