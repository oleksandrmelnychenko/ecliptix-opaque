#pragma once
/**
 * @file bench_utils.h
 * @brief Shared benchmark utilities — timing, statistics, platform info, CSV output.
 */

#include <chrono>
#include <vector>
#include <algorithm>
#include <numeric>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <string>
#include <functional>

#ifdef __APPLE__
#include <sys/sysctl.h>
#include <mach/mach_time.h>
#endif

namespace bench {

struct Stats {
    double min_us;
    double max_us;
    double mean_us;
    double median_us;
    double stddev_us;
    double p95_us;
    double p99_us;
    size_t iterations;
};

inline Stats compute_stats(std::vector<double>& samples_us) {
    Stats s{};
    s.iterations = samples_us.size();
    if (samples_us.empty()) return s;

    std::sort(samples_us.begin(), samples_us.end());

    s.min_us = samples_us.front();
    s.max_us = samples_us.back();
    s.median_us = samples_us[samples_us.size() / 2];

    double sum = std::accumulate(samples_us.begin(), samples_us.end(), 0.0);
    s.mean_us = sum / static_cast<double>(s.iterations);

    double sq_sum = 0.0;
    for (double v : samples_us) {
        double diff = v - s.mean_us;
        sq_sum += diff * diff;
    }
    s.stddev_us = std::sqrt(sq_sum / static_cast<double>(s.iterations));

    auto percentile = [&](double p) -> double {
        double idx = p * static_cast<double>(s.iterations - 1);
        size_t lo = static_cast<size_t>(idx);
        size_t hi = lo + 1;
        if (hi >= s.iterations) hi = s.iterations - 1;
        double frac = idx - static_cast<double>(lo);
        return samples_us[lo] * (1.0 - frac) + samples_us[hi] * frac;
    };

    s.p95_us = percentile(0.95);
    s.p99_us = percentile(0.99);

    return s;
}

/**
 * Run a benchmark: execute `fn` for `warmup` rounds (discarded),
 * then `iterations` rounds, collecting timing per call.
 */
inline Stats run_benchmark(const std::function<void()>& fn,
                           size_t iterations = 1000,
                           size_t warmup = 50) {
    /* Warmup */
    for (size_t i = 0; i < warmup; ++i) {
        fn();
    }

    std::vector<double> samples;
    samples.reserve(iterations);

    for (size_t i = 0; i < iterations; ++i) {
        auto t0 = std::chrono::high_resolution_clock::now();
        fn();
        auto t1 = std::chrono::high_resolution_clock::now();
        double us = std::chrono::duration<double, std::micro>(t1 - t0).count();
        samples.push_back(us);
    }

    return compute_stats(samples);
}

inline void print_stats(const char* name, const Stats& s) {
    std::printf("%-45s  %8.1f  %8.1f  %8.1f  %8.1f  %8.1f  %8.1f  %zu\n",
                name, s.mean_us, s.median_us, s.stddev_us,
                s.min_us, s.p95_us, s.p99_us, s.iterations);
}

inline void print_header() {
    std::printf("%-45s  %8s  %8s  %8s  %8s  %8s  %8s  %s\n",
                "Operation", "Mean(us)", "Med(us)", "StdDev", "Min(us)", "P95(us)", "P99(us)", "N");
    std::printf("%s\n", std::string(120, '-').c_str());
}

inline void print_separator(const char* section) {
    std::printf("\n=== %s ===\n", section);
    print_header();
}

/**
 * Print platform information for reproducibility.
 */
inline void print_platform_info() {
    std::printf("\n=== Platform Information ===\n");

#ifdef __APPLE__
    {
        char brand[256] = {};
        size_t len = sizeof(brand);
        if (sysctlbyname("machdep.cpu.brand_string", brand, &len, nullptr, 0) == 0) {
            std::printf("CPU:        %s\n", brand);
        }
        int ncpu = 0;
        len = sizeof(ncpu);
        if (sysctlbyname("hw.ncpu", &ncpu, &len, nullptr, 0) == 0) {
            std::printf("CPU Cores:  %d\n", ncpu);
        }
        uint64_t mem = 0;
        len = sizeof(mem);
        if (sysctlbyname("hw.memsize", &mem, &len, nullptr, 0) == 0) {
            std::printf("RAM:        %llu MB\n", mem / (1024 * 1024));
        }
    }
#elif defined(__linux__)
    {
        FILE* f = fopen("/proc/cpuinfo", "r");
        if (f) {
            char line[512];
            while (fgets(line, sizeof(line), f)) {
                if (strncmp(line, "model name", 10) == 0) {
                    char* colon = strchr(line, ':');
                    if (colon) std::printf("CPU:        %s", colon + 2);
                    break;
                }
            }
            fclose(f);
        }
        f = fopen("/proc/meminfo", "r");
        if (f) {
            char line[256];
            if (fgets(line, sizeof(line), f)) {
                long kb = 0;
                if (sscanf(line, "MemTotal: %ld kB", &kb) == 1) {
                    std::printf("RAM:        %ld MB\n", kb / 1024);
                }
            }
            fclose(f);
        }
    }
#endif

#if defined(__clang__)
    std::printf("Compiler:   Clang %d.%d.%d\n", __clang_major__, __clang_minor__, __clang_patchlevel__);
#elif defined(__GNUC__)
    std::printf("Compiler:   GCC %d.%d.%d\n", __GNUC__, __GNUC_MINOR__, __GNUC_PATCHLEVEL__);
#elif defined(_MSC_VER)
    std::printf("Compiler:   MSVC %d\n", _MSC_VER);
#endif

#ifdef __OPTIMIZE__
    std::printf("Opt Level:  Optimized\n");
#else
    std::printf("Opt Level:  Debug (unoptimized)\n");
#endif

#if defined(__x86_64__) || defined(_M_X64)
    std::printf("Arch:       x86_64\n");
#elif defined(__aarch64__) || defined(_M_ARM64)
    std::printf("Arch:       aarch64 (ARM64)\n");
#endif

    std::printf("C++ Std:    C++%ld\n", __cplusplus);
    std::printf("\n");
}

/**
 * CSV output for scripting / charting.
 */
inline void print_csv_header() {
    std::printf("operation,mean_us,median_us,stddev_us,min_us,p95_us,p99_us,iterations\n");
}

inline void print_csv_row(const char* name, const Stats& s) {
    std::printf("%s,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%zu\n",
                name, s.mean_us, s.median_us, s.stddev_us,
                s.min_us, s.p95_us, s.p99_us, s.iterations);
}

} // namespace bench
