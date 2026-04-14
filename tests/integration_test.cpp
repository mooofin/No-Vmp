#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>
#include <vector>
#include <cstdint>

namespace fs = std::filesystem;

class IntegrationTest : public ::testing::Test {
protected:
    fs::path testdata_dir() {
        const char* srcdir = std::getenv("TEST_SRCDIR");
        if (srcdir) return fs::path(srcdir) / "_main/samples";
        return fs::path("samples");
    }

    std::vector<uint8_t> read_file(const fs::path& p) {
        std::ifstream f(p, std::ios::binary);
        if (!f) return {};
        return { std::istreambuf_iterator<char>(f), {} };
    }
};

TEST_F(IntegrationTest, SampleFilesExist) {
    auto dir = testdata_dir();
    EXPECT_TRUE(fs::exists(dir / "sample1.bin"));
    EXPECT_TRUE(fs::exists(dir / "sample1.vmp.bin"));
}

TEST_F(IntegrationTest, SamplesAreValidBinary) {
    auto dir = testdata_dir();
    auto data = read_file(dir / "sample1.bin");
    if (data.empty()) GTEST_SKIP() << "sample1.bin not found";

    ASSERT_GE(data.size(), 4);
    bool is_pe = (data[0] == 'M' && data[1] == 'Z');
    bool is_elf = (data[0] == 0x7F && data[1] == 'E' && data[2] == 'L' && data[3] == 'F');
    EXPECT_TRUE(is_pe || is_elf) << "Sample should be PE or ELF";
}

TEST_F(IntegrationTest, DISABLED_FullLiftTest) {
    GTEST_SKIP() << "Full lifting requires LLVM";
}
