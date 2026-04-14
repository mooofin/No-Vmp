"""Configure system LLVM for Bazel."""

def _llvm_impl(repository_ctx):
    """Detect and configure system LLVM."""
    # Find llvm-config
    llvm_config = repository_ctx.which("llvm-config")
    if llvm_config == None:
        # Try with version suffixes
        for version in ["20", "19", "18", "17", "16", "15", "14"]:
            llvm_config = repository_ctx.which("llvm-config-" + version)
            if llvm_config != None:
                break
    
    if llvm_config == None:
        fail("llvm-config not found. Please install LLVM.")
    
    # Get LLVM configuration
    result = repository_ctx.execute([llvm_config, "--version"])
    if result.return_code != 0:
        fail("Failed to get LLVM version: " + result.stderr)
    llvm_version = result.stdout.strip()
    
    result = repository_ctx.execute([llvm_config, "--includedir"])
    if result.return_code != 0:
        fail("Failed to get LLVM include dir: " + result.stderr)
    llvm_includes = result.stdout.strip()
    
    result = repository_ctx.execute([llvm_config, "--libdir"])
    if result.return_code != 0:
        fail("Failed to get LLVM lib dir: " + result.stderr)
    llvm_libdir = result.stdout.strip()
    
    result = repository_ctx.execute([llvm_config, "--libs", "core", "support", "irreader", "passes", "analysis", "transformutils", "instcombine", "scalaropts"])
    if result.return_code != 0:
        fail("Failed to get LLVM libs: " + result.stderr)
    llvm_libs_output = result.stdout.strip()
    
    result = repository_ctx.execute([llvm_config, "--ldflags"])
    if result.return_code != 0:
        fail("Failed to get LLVM ldflags: " + result.stderr)
    llvm_ldflags = result.stdout.strip()
    
    # Generate BUILD file
    build_content = """load("@rules_cc//cc:defs.bzl", "cc_library")
package(default_visibility = ["//visibility:public"])

cc_library(
    name = "llvm",
    hdrs = glob(
        ["include/llvm/**/*.h"],
        allow_empty = True,
    ) + glob(
        ["include/llvm-c/**/*.h"],
        allow_empty = True,
    ),
    includes = ["include"],
    linkopts = ["-lLLVM"],
)
"""
    
    # Create symlinks to LLVM headers and libs
    repository_ctx.symlink(llvm_includes, "include")
    repository_ctx.symlink(llvm_libdir, "lib")
    
    repository_ctx.file("BUILD.bazel", build_content)
    
    print("Configured LLVM " + llvm_version + " from " + str(llvm_config))

llvm_configure = repository_rule(
    implementation = _llvm_impl,
    local = True,
)
