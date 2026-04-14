load("@rules_cc//cc:defs.bzl", "cc_library")

package(default_visibility = ["//visibility:private"])

cc_library(
    name = "stream",
    srcs = ["stream.cpp"],
    hdrs = ["stream.hpp"],
    includes = [".."],
    visibility = [
        "//lib/vmp:__pkg__",
        "//tests:__pkg__",
    ],
    implementation_deps = [
        "//third_party/linux-pe:linux_pe",
    ],
    deps = [
        "@capstone//:capstone",
    ],
)
