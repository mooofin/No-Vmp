load("@rules_cc//cc:defs.bzl", "cc_binary")

package(default_visibility = ["//visibility:private"])

cc_binary(
    name = "lift_bench",
    srcs = ["lift_bench.cpp"],
    deps = [
        "//lib/vmp:vmp",
        "@google_benchmark//:benchmark",
    ],
)
