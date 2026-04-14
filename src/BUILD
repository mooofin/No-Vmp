load("@rules_cc//cc:defs.bzl", "cc_binary")

package(default_visibility = ["//visibility:private"])

cc_binary(
    name = "novmp",
    srcs = ["main.cpp"],
    visibility = ["//visibility:public"],
    deps = [
        "//lib/vmp:vmp",
        "@cli11//:cli11",
    ],
    linkopts = select({
        "@bazel_tools//src/conditions:darwin": [],
        "@bazel_tools//src/conditions:linux": ["-lpthread"],
        "//conditions:default": [],
    }),
)
