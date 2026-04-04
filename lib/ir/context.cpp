#include "context.hpp"
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Support/raw_os_ostream.h>
#include <llvm/Bitcode/BitcodeWriter.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Transforms/InstCombine/InstCombine.h>
#include <llvm/Transforms/Scalar.h>
#include <llvm/Transforms/Scalar/GVN.h>
#include <llvm/Transforms/Utils.h>
#include <sstream>
#include <stdexcept>

namespace vmp::ir {

LiftContext::LiftContext(std::string name, uint64_t image_base) {
    ctx_ = std::make_unique<llvm::LLVMContext>();
    mod_ = std::make_unique<llvm::Module>(name, *ctx_);
    builder_ = std::make_unique<llvm::IRBuilder<>>(*ctx_);
    
    // Create void(void) function
    llvm::FunctionType* fn_type = llvm::FunctionType::get(
        llvm::Type::getVoidTy(*ctx_), false);
    fn_ = llvm::Function::Create(fn_type, llvm::Function::ExternalLinkage, name, mod_.get());
    
    // Create entry block
    llvm::BasicBlock* entry = llvm::BasicBlock::Create(*ctx_, "entry", fn_);
    builder_->SetInsertPoint(entry);
    
    // Create VSP alloca at entry
    vsp_ = builder_->CreateAlloca(
        llvm::Type::getInt64Ty(*ctx_), nullptr, "vsp");
    
    // Create flags alloca
    flags_ = builder_->CreateAlloca(
        llvm::Type::getInt64Ty(*ctx_), nullptr, "flags");
}

LiftContext::~LiftContext() = default;

llvm::AllocaInst* LiftContext::get_vreg(uint8_t idx, unsigned bits) {
    uint32_t key = (idx << 8) | bits;
    auto it = vregs_.find(key);
    if (it != vregs_.end()) return it->second;
    
    // Create new alloca at function entry
    llvm::BasicBlock* entry = &fn_->getEntryBlock();
    llvm::IRBuilder<> tmp_builder(entry, entry->begin());
    
    auto* alloca = tmp_builder.CreateAlloca(
        llvm::IntegerType::get(*ctx_, bits), nullptr,
        "vr" + std::to_string(idx));
    vregs_[key] = alloca;
    return alloca;
}

llvm::AllocaInst* LiftContext::get_vsp() {
    return vsp_;
}

llvm::AllocaInst* LiftContext::get_flags() {
    return flags_;
}

void LiftContext::optimize() {
    // Create the analysis managers
    llvm::LoopAnalysisManager lam;
    llvm::FunctionAnalysisManager fam;
    llvm::CGSCCAnalysisManager cgam;
    llvm::ModuleAnalysisManager mam;
    
    // Create the pass builder
    llvm::PassBuilder pb;
    
    // Register all the basic analyses with the managers
    pb.registerModuleAnalyses(mam);
    pb.registerCGSCCAnalyses(cgam);
    pb.registerFunctionAnalyses(fam);
    pb.registerLoopAnalyses(lam);
    pb.crossRegisterProxies(lam, fam, cgam, mam);
    
    // Create the module pass manager with O2 pipeline
    llvm::ModulePassManager mpm = pb.buildModuleSimplificationPipeline(
        llvm::OptimizationLevel::O2,
        llvm::ThinOrFullLTOPhase::None);
    
    // Run the passes
    mpm.run(*mod_, mam);
    
    // Verify the module
    std::string error_str;
    llvm::raw_string_ostream error_stream(error_str);
    if (llvm::verifyModule(*mod_, &error_stream)) {
        throw std::runtime_error("Module verification failed: " + error_str);
    }
}

std::string LiftContext::to_ir_string() const {
    std::string str;
    llvm::raw_string_ostream os(str);
    mod_->print(os, nullptr);
    return str;
}

std::vector<uint8_t> LiftContext::to_bitcode() const {
    std::string str;
    llvm::raw_string_ostream os(str);
    llvm::WriteBitcodeToFile(*mod_, os);
    os.flush();
    return std::vector<uint8_t>(str.begin(), str.end());
}

} // namespace vmp::ir
