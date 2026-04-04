#pragma once
#include <memory>
#include <cstdint>
#include "vm_state.hpp"
#include "image_desc.hpp"
#include "../ir/context.hpp"

namespace vmp {

// Main lifter interface
LiftedRoutine lift(VmState& state);

} // namespace vmp
