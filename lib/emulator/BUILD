load("@rules_cc//cc:defs.bzl", "cc_library")

package(default_visibility = ["//visibility:private"])

cc_library(
    name = "rwx_allocator",
    srcs = ["rwx_allocator.cpp"],
    hdrs = ["rwx_allocator.hpp"],
    includes = [".."],
    visibility = [":__subpackages__"],
    implementation_deps = [
        "//third_party/linux-pe:linux_pe",
    ],
)

cc_library(
    name = "emulator",
    srcs = ["emulator.cpp"],
    hdrs = ["emulator.hpp"],
    includes = [".."],
    visibility = [
        "//lib/vmp:__pkg__",
        "//tests:__pkg__",
    ],
    deps = [
        ":rwx_allocator",
        "//third_party/linux-pe:linux_pe",
    ],
)
