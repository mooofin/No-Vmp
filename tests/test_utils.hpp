#pragma once
#include <gtest/gtest.h>
#include <vector>
#include <cstdint>

namespace test_utils {

inline std::vector<uint8_t> make_bytes(std::initializer_list<uint8_t> list) {
    return std::vector<uint8_t>(list);
}

inline void dump_bytes(const std::vector<uint8_t>& bytes) {
    for (auto b : bytes) printf("%02x ", b);
    printf("\n");
}

} // namespace test_utils
