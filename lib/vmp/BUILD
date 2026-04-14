load("@rules_cc//cc:defs.bzl", "cc_library")

package(default_visibility = ["//visibility:private"])

cc_library(
    name = "vmp",
    srcs = [
        "image_desc.cpp",
        "vm_state.cpp",
        "architecture.cpp",
        "rkey.cpp",
        "subroutines.cpp",
        "lifter.cpp",
        "//lib/ir:context.cpp",
        "//lib/ir:vmp_to_llvm.cpp",
    ],
    hdrs = [
        "image_desc.hpp",
        "vm_state.hpp",
        "architecture.hpp",
        "rkey.hpp",
        "subroutines.hpp",
        "lifter.hpp",
        "//lib/ir:context.hpp",
        "//lib/ir:vmp_to_llvm.hpp",
    ],
    includes = [".."],
    visibility = [
        "//:__pkg__",
        "//src:__pkg__",
        "//tests:__pkg__",
        "//tests/fuzz:__pkg__",
    ],
    implementation_deps = [
        "@llvm//:llvm",
    ],
    deps = [
        "//lib/disasm:stream",
        "//lib/emulator",
        "//third_party/linux-pe:linux_pe",
    ],
)

alias(
    name = "novmp_lib",
    actual = ":vmp",
    visibility = ["//visibility:public"],
)
