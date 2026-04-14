# Bazel workspace for No-Vmp
workspace(name = "no_vmp")

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

# rules_cc - C++ rules for Bazel
http_archive(
    name = "rules_cc",
    urls = ["https://github.com/bazelbuild/rules_cc/releases/download/0.0.9/rules_cc-0.0.9.tar.gz"],
    sha256 = "2037875b9a4456dce4a79d112a8ae885bbc4aad774e6221a1724f40c7322f0f8",
)

# CLI11 - command line parsing library
http_archive(
    name = "cli11",
    urls = ["https://github.com/CLIUtils/CLI11/archive/refs/tags/v2.4.2.tar.gz"],
    strip_prefix = "CLI11-2.4.2",
    build_file_content = """
load("@rules_cc//cc:defs.bzl", "cc_library")
cc_library(
    name = "cli11",
    hdrs = glob(["include/**/*.hpp"]),
    includes = ["include"],
    visibility = ["//visibility:public"],
)
""",
)

# System LLVM repository - uses llvm-config to detect system LLVM
load("//:llvm_configure.bzl", "llvm_configure")
llvm_configure(name = "llvm")

# System Capstone repository
load("//:capstone_configure.bzl", "capstone_configure")
capstone_configure(name = "capstone")
