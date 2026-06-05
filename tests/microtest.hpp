#pragma once
// A ~50-line, zero-dependency test harness — verify with just a C++ compiler.
#include <cstdio>
#include <cstddef>
#include <exception>
#include <vector>

namespace microtest {

struct TestCase { const char* name; void (*fn)(); };

inline std::vector<TestCase>& registry() { static std::vector<TestCase> r; return r; }
inline int&         failCount() { static int f = 0; return f; }
inline const char*& current()   { static const char* c = ""; return c; }

struct Registrar {
    Registrar(const char* name, void (*fn)()) { registry().push_back({name, fn}); }
};

inline void fail(const char* expr, const char* file, int line) {
    std::printf("  FAIL [%s]  %s:%d  %s\n", current(), file, line, expr);
    ++failCount();
}

inline int run() {
    int passed = 0;
    for (auto& tc : registry()) {
        current() = tc.name;
        const int before = failCount();
        try {
            tc.fn();
        } catch (const std::exception& e) {
            std::printf("  FAIL [%s]  threw: %s\n", tc.name, e.what());
            ++failCount();
        } catch (...) {
            std::printf("  FAIL [%s]  threw unknown exception\n", tc.name);
            ++failCount();
        }
        if (failCount() == before) {
            ++passed;
            std::printf("  ok    %s\n", tc.name);
        }
    }
    std::printf("\n%d/%d tests passed, %d checks failed\n",
                passed, static_cast<int>(registry().size()), failCount());
    return failCount() == 0 ? 0 : 1;
}

} // namespace microtest

#define MT_CAT_(a, b) a##b
#define MT_CAT(a, b)  MT_CAT_(a, b)

#define TEST(name)                                                            \
    static void MT_CAT(mt_test_, __LINE__)();                                 \
    static ::microtest::Registrar MT_CAT(mt_reg_, __LINE__){                  \
        name, MT_CAT(mt_test_, __LINE__)};                                    \
    static void MT_CAT(mt_test_, __LINE__)()

#define CHECK(cond)                                                           \
    do { if (!(cond)) ::microtest::fail(#cond, __FILE__, __LINE__); } while (0)

#define CHECK_EQ(a, b)                                                        \
    do { if (!((a) == (b)))                                                   \
        ::microtest::fail(#a " == " #b, __FILE__, __LINE__); } while (0)
