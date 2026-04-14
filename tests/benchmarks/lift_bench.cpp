#include <benchmark/benchmark.h>
#include <vector>
#include <cstdint>

static void BM_VectorCreate(benchmark::State& state) {
    for (auto _ : state) {
        std::vector<uint8_t> v(1024, 0x90);
        benchmark::DoNotOptimize(v.data());
        benchmark::ClobberMemory();
    }
}
BENCHMARK(BM_VectorCreate);

BENCHMARK_MAIN();
