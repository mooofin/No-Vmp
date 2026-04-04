#pragma once
#include <vector>
#include <optional>
#include <string>
#include <span>
#include <functional>
#include <memory>
#include <algorithm>
#include <unordered_map>
#include <shared_mutex>
#include <mutex>
#include <cstdint>
#include <capstone/capstone.h>

namespace vmp::disasm {

// Thin RAII wrapper around a single capstone instruction.
struct Insn {
    cs_insn raw;

    [[nodiscard]] bool is(unsigned id, std::span<const x86_op_type> ops) const noexcept;
    [[nodiscard]] std::string to_string() const;
    [[nodiscard]] auto address() const noexcept { return raw.address; }
    [[nodiscard]] auto id()      const noexcept { return raw.id; }
    [[nodiscard]] std::span<const cs_x86_op> operands() const noexcept;
    [[nodiscard]] std::span<const uint8_t>   bytes()    const noexcept;
};

// Ordered, index-tagged stream of disassembled x86-64 instructions.
// The index tag (first in the pair) is the original emission order from
// the deobfuscator — survives reordering passes.
class Stream {
public:
    using Entry = std::pair<int, Insn>;

    Stream() = default;
    explicit Stream(std::vector<Entry> entries) : entries_(std::move(entries)) {}

    // Indexed access (strips the tag)
    [[nodiscard]] const Insn& operator[](std::size_t n) const { return entries_[n].second; }
    [[nodiscard]] std::size_t size() const noexcept { return entries_.size(); }
    [[nodiscard]] bool empty()       const noexcept { return entries_.empty(); }

    // Merge two streams, dedup by tag, sort by original order.
    [[nodiscard]] Stream operator+(const Stream& rhs) const;
    Stream& normalize();

    // Serialise to raw bytes (after normalize).
    [[nodiscard]] std::vector<uint8_t> to_bytes() const;

    // Predicate-based search — return index or -1.
    template<typename Pred>
    [[nodiscard]] int find_next(Pred pred, int from = 0) const {
        for (int i = from; i < static_cast<int>(entries_.size()); ++i)
            if (pred(entries_[i].second)) return i;
        return -1;
    }
    
    template<typename Pred>
    [[nodiscard]] int find_prev(Pred pred, int from = -1) const {
        if (from == -1) from = static_cast<int>(entries_.size()) - 1;
        for (int i = from; i >= 0; --i)
            if (pred(entries_[i].second)) return i;
        return -1;
    }

    // Convenience overloads for (id, operand-type-list) pattern.
    [[nodiscard]] int find_next(unsigned id, std::span<const x86_op_type> ops, int from = 0) const;
    [[nodiscard]] int find_prev(unsigned id, std::span<const x86_op_type> ops, int from = -1) const;

    void erase_front(int n);
    void erase_range(int start, int end);  // Erase entries [start, end)
    void truncate_at(int index);  // Remove all entries from index onwards

    [[nodiscard]] std::string dump() const;

    // Raw entry access for callers that need the tag.
    [[nodiscard]] const std::vector<Entry>& entries() const noexcept { return entries_; }
    // Non-const version for internal use
    [[nodiscard]] std::vector<Entry>& entries() noexcept { return entries_; }

private:
    std::vector<Entry> entries_;
};

// Backward register-def trace result - defined after Stream is complete
struct TraceResult { 
    Stream defs; 
    std::vector<x86_reg> deps; 
};

// Forward declaration
TraceResult trace_def(const Stream& stream, x86_reg reg, int end, int begin = 0);

// Thread-safe, lazy disassembly + control-flow straightening cache.
// Replaces the file-static map in the old deobfuscator.hpp.
class Deobfuscator {
public:
    // Construct with a borrowed pointer to raw PE bytes + RVA → ptr resolver.
    using RvaToPtr = std::function<const uint8_t*(uint32_t rva)>;
    explicit Deobfuscator(RvaToPtr resolver);
    ~Deobfuscator();

    // Returns the linearised, jmp-chased instruction stream starting at `rva`.
    // Result is cached; thread-safe.
    [[nodiscard]] Stream get(uint32_t rva);

    // Invalidate a single entry (e.g. after patching).
    void invalidate(uint32_t rva);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace vmp::disasm
