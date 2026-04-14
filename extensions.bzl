"""Module extensions for Bazel bzlmod."""

load("//:llvm_configure.bzl", "llvm_configure")
load("//:capstone_configure.bzl", "capstone_configure")

def _llvm_extension_impl(module_ctx):
    llvm_configure(name = "llvm")

capstone = module_extension(
    implementation = lambda ctx: capstone_configure(name = "capstone"),
)

llvm = module_extension(
    implementation = _llvm_extension_impl,
)
