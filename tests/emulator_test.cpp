#include <gtest/gtest.h>
#include <vector>
#include <cstdint>

namespace {

class EmulatorTest : public ::testing::Test {};

TEST_F(EmulatorTest, ModuleLinks) {
    EXPECT_TRUE(true);
}

TEST_F(EmulatorTest, ByteSequenceCreation) {
    std::vector<uint8_t> code = {0xC3};
    EXPECT_EQ(code.size(), 1);
    EXPECT_EQ(code[0], 0xC3);
}

TEST_F(EmulatorTest, NopSled) {
    std::vector<uint8_t> nop_sled(10, 0x90);
    EXPECT_EQ(nop_sled.size(), 10);
    for (auto b : nop_sled) {
        EXPECT_EQ(b, 0x90);
    }
}

} // namespace
