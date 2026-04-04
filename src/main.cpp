#include <CLI/CLI.hpp>
#include <filesystem>
#include <fstream>
#include <print>
#include <vector>
#include <thread>
#include <semaphore>
#include <atomic>
#include <format>

// Simple RAII scope guard (since std::scope_exit is not widely available)
template<typename F>
struct ScopeExit {
    F f;
    ScopeExit(F f) : f(f) {}
    ~ScopeExit() { f(); }
};
template<typename F>
ScopeExit(F) -> ScopeExit<F>;

#include "vmp/image_desc.hpp"
#include "ir/vmp_to_llvm.hpp"

namespace fs = std::filesystem;

// List of vmp section names, used to chain VMs, detecting re-entry.
inline std::vector<std::string> g_section_prefixes = { ".vmp" };

static std::vector<uint8_t> read_file(const fs::path& p) {
    std::ifstream f(p, std::ios::binary);
    if (!f) throw std::runtime_error(std::format("Cannot open: {}", p.string()));
    return { std::istreambuf_iterator<char>(f), {} };
}

int main(int argc, char** argv) {
    CLI::App app{"NoVmp — VMProtect x64 3.x static devirtualizer"};

    fs::path           input_path;
    uint64_t           override_base  = 0;
    std::vector<uint32_t> target_rvas;
    std::vector<std::string> extra_sections;
    bool               no_opt         = false;
    bool               strip_const    = false;
    bool               recompile      = false;
    unsigned           jobs           = std::thread::hardware_concurrency();
    fs::path           output_dir;

    app.add_option("input", input_path, "Unpacked PE binary")->required()->check(CLI::ExistingFile);
    app.add_option("--base,-b",     override_base,   "Override image base (hex)");
    app.add_option("--vms",         target_rvas,     "Specific VMEnter RVAs (hex)");
    app.add_option("--sections",    extra_sections,  "Extra VMP section name prefixes");
    app.add_flag  ("--no-opt",      no_opt,          "Disable LLVM optimisation passes");
    app.add_flag  ("--const-deobf", strip_const,     "Strip constant obfuscation");
    app.add_flag  ("--recompile",   recompile,       "Experimental: patch binary with lifted code");
    app.add_option("--jobs,-j",     jobs,            "Parallel lift workers");
    app.add_option("--output,-o",   output_dir,      "Output directory (default: <input>.novmp/)");

    CLI11_PARSE(app, argc, argv);

    // Setup output dir.
    if (output_dir.empty())
        output_dir = input_path.parent_path() / (input_path.stem().string() + ".novmp");
    fs::create_directories(output_dir);

    // Load image.
    auto desc = std::make_unique<vmp::ImageDesc>(read_file(input_path), override_base);
    desc->opts.optimize              = !no_opt;
    desc->opts.strip_const_obfusc   = strip_const;
    desc->opts.experimental_recompile = recompile;

    // Add extra section prefixes.
    for (auto& s : extra_sections)
        g_section_prefixes.push_back(s);

    // Discover or set targets.
    if (target_rvas.empty())
        desc->discover_vmenter();
    else
        desc->set_target_rvas(target_rvas);

    std::println("[*] {} routines to lift", desc->routines().size());

    // Concurrent lifting with bounded parallelism.
    std::counting_semaphore sem(jobs);
    std::atomic<int> ok{0}, fail{0};
    std::vector<std::jthread> workers;

    for (auto& vr : desc->routines()) {
        workers.emplace_back([&, &vr_ = vr] {
            sem.acquire();
            auto guard = ScopeExit([&] { sem.release(); });

            try {
                vmp::VmState state{ desc.get(), vr_.jmp_rva };
                auto lctx = vmp::ir::lift_routine(state);

                if (desc->opts.optimize)
                    lctx->optimize();

                // Write .ll and .bc
                auto stem = std::format("{:08x}", vr_.jmp_rva);
                {
                    auto path = output_dir / (stem + ".ll");
                    std::ofstream f(path);
                    f << lctx->to_ir_string();
                }
                {
                    auto path = output_dir / (stem + ".bc");
                    auto bc   = lctx->to_bitcode();
                    std::ofstream f(path, std::ios::binary);
                    f.write(reinterpret_cast<const char*>(bc.data()), bc.size());
                }

                ++ok;
                std::println("[+] {:08x} lifted ({} instructions reduced)",
                             vr_.jmp_rva, 0 /* fill from lctx */);
            } catch (const std::exception& ex) {
                ++fail;
                std::println(stderr, "[-] {:08x} failed: {}", vr_.jmp_rva, ex.what());
            }
        });
    }
    workers.clear(); // join all

    std::println("[*] done: {} ok, {} failed", ok.load(), fail.load());
    return fail.load() ? 1 : 0;
}
