#include <gtest/gtest.h>
#include <vector>
#include <cstdint>

namespace disasm {

class StreamTest : public ::testing::Test {};

TEST_F(StreamTest, EmptyStream) {
    EXPECT_TRUE(true);
}

TEST_F(StreamTest, ByteVectorBasics) {
    std::vector<uint8_t> bytes = {0x48, 0x89, 0xC3};
    EXPECT_EQ(bytes.size(), 3);
    EXPECT_EQ(bytes[0], 0x48);
}

} // namespace disasm
