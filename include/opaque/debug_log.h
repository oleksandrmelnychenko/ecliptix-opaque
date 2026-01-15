#pragma once

// Development logging for OPAQUE protocol - always enabled
// Logs all keys and values to console for development purposes

#include <cstdint>
#include <cstdio>
#include <cstddef>

namespace ecliptix {
namespace security {
namespace opaque {
namespace log {

    inline void hex(const char* label, const uint8_t* data, size_t length) {
        if (!data || length == 0) {
            fprintf(stdout, "[OPAQUE] %s: (null or empty)\n", label);
            fflush(stdout);
            return;
        }
        fprintf(stdout, "[OPAQUE] %s (%zu bytes): ", label, length);
        for (size_t i = 0; i < length; ++i) {
            fprintf(stdout, "%02x", data[i]);
        }
        fprintf(stdout, "\n");
        fflush(stdout);
    }

    template<typename Container>
    inline void hex(const char* label, const Container& container) {
        hex(label, container.data(), container.size());
    }

    inline void msg(const char* msg) {
        fprintf(stdout, "[OPAQUE] %s\n", msg);
        fflush(stdout);
    }

    inline void section(const char* section) {
        fprintf(stdout, "\n[OPAQUE] ===== %s =====\n", section);
        fflush(stdout);
    }

} // namespace log
} // namespace opaque
} // namespace security
} // namespace ecliptix
