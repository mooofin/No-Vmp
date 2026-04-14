"""Configure system Capstone for Bazel."""

def _capstone_impl(repository_ctx):
    """Detect and configure system Capstone."""
    # Try pkg-config first
    pkg_config = repository_ctx.which("pkg-config")
    capstone_cflags = ""
    capstone_libs = ""
    
    if pkg_config != None:
        result = repository_ctx.execute([pkg_config, "--cflags", "capstone"])
        if result.return_code == 0:
            capstone_cflags = result.stdout.strip()
        
        result = repository_ctx.execute([pkg_config, "--libs", "capstone"])
        if result.return_code == 0:
            capstone_libs = result.stdout.strip()
    
    # Find capstone header
    capstone_include = "/usr/include"
    for path in ["/usr/include/capstone", "/usr/local/include/capstone", "/opt/homebrew/include/capstone"]:
        if repository_ctx.path(path + "/capstone.h").exists:
            capstone_include = path
            break
    
    # Generate BUILD file
    build_content = """load("@rules_cc//cc:defs.bzl", "cc_library")
package(default_visibility = ["//visibility:public"])

cc_library(
    name = "capstone",
    hdrs = glob(["include/**/*.h"]),
    includes = ["include"],
    linkopts = ["-lcapstone"],
)
"""
    
    # Create symlink to capstone headers
    repository_ctx.symlink(capstone_include, "include")
    
    repository_ctx.file("BUILD.bazel", build_content)
    
    print("Configured Capstone from " + capstone_include)

capstone_configure = repository_rule(
    implementation = _capstone_impl,
    local = True,
)
