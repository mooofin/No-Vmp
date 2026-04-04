#pragma once
#include "../vmp/vm_state.hpp"
#include "../vmp/architecture.hpp"
#include "context.hpp"
#include <llvm/IR/BasicBlock.h>

namespace vmp::ir {

// Translates one classified VMP IL instruction into LLVM IR.
// `builder` must be positioned at the insertion point inside `fn`.
// Returns the outgoing IR basic block (may differ from entry if the
// instruction introduces branches).
llvm::BasicBlock* translate(LiftContext& lctx,
                             llvm::BasicBlock* bb,
                             const arch::Instruction& insn);

// Full routine lifter: drives VmState, calls translate() per IL instruction,
// chains VM exits / swaps.  Returns the populated LiftContext.
std::unique_ptr<LiftContext> lift_routine(VmState& state);

} // namespace vmp::ir
