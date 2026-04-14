#include <gtest/gtest.h>
#include <capstone/capstone.h>
#include "lib/vmp/rkey.hpp"

namespace vmp {

class RkeyTest : public ::testing::Test {};

TEST_F(RkeyTest, ExtendRegBasic) {
    EXPECT_EQ(extend_reg(X86_REG_AL), X86_REG_RAX);
    EXPECT_EQ(extend_reg(X86_REG_AH), X86_REG_RAX);
    EXPECT_EQ(extend_reg(X86_REG_BL), X86_REG_RBX);
    EXPECT_EQ(extend_reg(X86_REG_AX), X86_REG_RAX);
    EXPECT_EQ(extend_reg(X86_REG_BX), X86_REG_RBX);
    EXPECT_EQ(extend_reg(X86_REG_EAX), X86_REG_RAX);
    EXPECT_EQ(extend_reg(X86_REG_EBX), X86_REG_RBX);
    EXPECT_EQ(extend_reg(X86_REG_RAX), X86_REG_RAX);
    EXPECT_EQ(extend_reg(X86_REG_RBX), X86_REG_RBX);
}

TEST_F(RkeyTest, ExtendRegR8R15) {
    EXPECT_EQ(extend_reg(X86_REG_R8B), X86_REG_R8);
    EXPECT_EQ(extend_reg(X86_REG_R8W), X86_REG_R8);
    EXPECT_EQ(extend_reg(X86_REG_R8D), X86_REG_R8);
    EXPECT_EQ(extend_reg(X86_REG_R8), X86_REG_R8);
    EXPECT_EQ(extend_reg(X86_REG_R15B), X86_REG_R15);
    EXPECT_EQ(extend_reg(X86_REG_R15W), X86_REG_R15);
    EXPECT_EQ(extend_reg(X86_REG_R15D), X86_REG_R15);
    EXPECT_EQ(extend_reg(X86_REG_R15), X86_REG_R15);
}

TEST_F(RkeyTest, ExtendRegSpecial) {
    EXPECT_EQ(extend_reg(X86_REG_SPL), X86_REG_RSP);
    EXPECT_EQ(extend_reg(X86_REG_BPL), X86_REG_RBP);
    EXPECT_EQ(extend_reg(X86_REG_SIL), X86_REG_RSI);
    EXPECT_EQ(extend_reg(X86_REG_DIL), X86_REG_RDI);
}

TEST_F(RkeyTest, DISABLED_ExtractRkeyFull) {
    GTEST_SKIP() << "Needs VmState + disasm::Stream setup";
}

} // namespace vmp
