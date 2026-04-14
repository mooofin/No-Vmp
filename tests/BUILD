load("@rules_cc//cc:defs.bzl", "cc_test", "cc_library")

package(default_visibility = ["//visibility:private"])

cc_library(
    name = "test_utils",
    testonly = True,
    hdrs = ["test_utils.hpp"],
    includes = ["."],
    visibility = ["//tests:__subpackages__"],
    deps = ["@com_google_googletest//:gtest"],
)

cc_test(
    name = "rkey_test",
    size = "small",
    srcs = ["rkey_test.cpp"],
    deps = [
        "//lib/vmp:vmp",
        "@com_google_googletest//:gtest",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "disasm_test",
    size = "small",
    srcs = ["disasm_test.cpp"],
    deps = [
        "//lib/disasm:stream",
        "@com_google_googletest//:gtest",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "emulator_test",
    size = "small",
    srcs = ["emulator_test.cpp"],
    deps = [
        "//lib/emulator:emulator",
        "@com_google_googletest//:gtest",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "integration_test",
    size = "small",
    timeout = "short",
    srcs = ["integration_test.cpp"],
    data = ["//samples:test_binaries"],
    deps = [
        "//lib/vmp:vmp",
        "@com_google_googletest//:gtest",
        "@com_google_googletest//:gtest_main",
    ],
)

test_suite(
    name = "all_tests",
    tests = [
        ":rkey_test",
        ":disasm_test",
        ":emulator_test",
        ":integration_test",
    ],
    visibility = ["//:__pkg__"],
)

alias(
    name = "tests",
    actual = ":all_tests",
    visibility = ["//:__pkg__"],
)
