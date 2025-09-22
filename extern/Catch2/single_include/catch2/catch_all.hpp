#pragma once

#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>
#include <functional>

#define CATCH_VERSION_MAJOR 3
#define CATCH_VERSION_MINOR 7
#define CATCH_VERSION_PATCH 1

namespace Catch {

    struct TestCase {
        std::string name;
        std::function<void()> test_func;
        std::string file;
        int line;

        TestCase(const std::string& n, std::function<void()> f, const std::string& file_name, int line_num)
            : name(n), test_func(f), file(file_name), line(line_num) {}
    };

    class TestRegistry {
    public:
        static TestRegistry& instance() {
            static TestRegistry inst;
            return inst;
        }

        void add_test(const TestCase& test) {
            tests.push_back(test);
        }

        int run_all_tests() {
            int failed = 0;
            std::cout << "Running " << tests.size() << " test cases..." << std::endl;

            for (const auto& test : tests) {
                try {
                    std::cout << "Running: " << test.name << "..." << std::flush;
                    test.test_func();
                    std::cout << " PASSED" << std::endl;
                } catch (const std::exception& e) {
                    std::cout << " FAILED: " << e.what() << std::endl;
                    failed++;
                } catch (...) {
                    std::cout << " FAILED: Unknown exception" << std::endl;
                    failed++;
                }
            }

            std::cout << "\nResults: " << (tests.size() - failed) << " passed, "
                      << failed << " failed" << std::endl;
            return failed;
        }

    private:
        std::vector<TestCase> tests;
    };

    struct TestRegistrar {
        TestRegistrar(const std::string& name, std::function<void()> func,
                     const std::string& file, int line) {
            TestRegistry::instance().add_test(TestCase(name, func, file, line));
        }
    };

    class AssertionException : public std::runtime_error {
    public:
        AssertionException(const std::string& msg) : std::runtime_error(msg) {}
    };

    template<typename T, typename U>
    void require_equal(const T& lhs, const U& rhs, const std::string& file, int line) {
        if (!(lhs == rhs)) {
            std::ostringstream oss;
            oss << "REQUIRE failed at " << file << ":" << line
                << " - Expected: " << rhs << ", Got: " << lhs;
            throw AssertionException(oss.str());
        }
    }

    template<typename T>
    void require_true(const T& expr, const std::string& file, int line, const std::string& expr_str) {
        if (!expr) {
            std::ostringstream oss;
            oss << "REQUIRE failed at " << file << ":" << line
                << " - Expression '" << expr_str << "' evaluated to false";
            throw AssertionException(oss.str());
        }
    }
}

#define TEST_CASE(name) \
    void test_##__LINE__(); \
    static Catch::TestRegistrar reg_##__LINE__(name, test_##__LINE__, __FILE__, __LINE__); \
    void test_##__LINE__()

#define REQUIRE(expr) \
    Catch::require_true(expr, __FILE__, __LINE__, #expr)

#define REQUIRE_EQ(lhs, rhs) \
    Catch::require_equal(lhs, rhs, __FILE__, __LINE__)

#define SECTION(name) \
    if (true)

inline int main_catch2() {
    return Catch::TestRegistry::instance().run_all_tests();
}