#include "lifter.hpp"
#include "ir/vmp_to_llvm.hpp"

namespace vmp {

LiftedRoutine lift(VmState& state) {
    LiftedRoutine result;
    
    // Call the IR lifter
    result.context = ir::lift_routine(state);
    
    // TODO: Populate stats
    result.handler_count = 0;
    result.instructions_before = 0;
    result.instructions_after = 0;
    
    return result;
}

} // namespace vmp
