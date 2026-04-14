#include "lifter.hpp"
#include "ir/vmp_to_llvm.hpp"
#include <span>

namespace vmp {

LiftedRoutine lift(VmState& state) {
    LiftedRoutine result;
    
    // Call the IR lifter with statistics tracking
    result.context = ir::lift_routine(state, result.handler_count, 
                                       result.instructions_before, 
                                       result.instructions_after);
    
    return result;
}

} // namespace vmp
