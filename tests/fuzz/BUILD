load("@rules_cc//cc:defs.bzl", "cc_test")

package(default_visibility = ["//visibility:private"])

# TODO: Enable when fuzzing setup complete
# cc_test(
#     name = "rkey_fuzz",
#     srcs = ["rkey_fuzz.cpp"],
#     deps = [
#         "//lib/vmp:vmp",
#     ],
#     linkopts = ["-fsanitize=fuzzer,address"],
#     args = ["$(location rkey_corpus)"],
#     data = [":rkey_corpus"],
# )

# filegroup(
#     name = "rkey_corpus",
#     srcs = glob(
#         ["corpus/**/*"],
#         allow_empty = True,
#     ),
# )

exports_files(["rkey_fuzz.cpp"])
