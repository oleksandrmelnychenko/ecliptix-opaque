#pragma once

#include <cstdint>
#include <cstddef>

#ifdef OPAQUE_DEBUG_LOGGING
#include <cstdio>
#warning "OPAQUE_DEBUG_LOGGING is enabled - DO NOT use in production builds!"
#endif

namespace ecliptix {
namespace security {
namespace opaque {
namespace log {

#ifdef OPAQUE_DEBUG_LOGGING

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

    inline void msg(const char* message) {
        fprintf(stdout, "[OPAQUE] %s\n", message);
        fflush(stdout);
    }

    inline void section(const char* section_name) {
        fprintf(stdout, "\n[OPAQUE] ===== %s =====\n", section_name);
        fflush(stdout);
    }

#else

    inline void hex(const char*, const uint8_t*, size_t) {}

    template<typename Container>
    inline void hex(const char*, const Container&) {}

    inline void msg(const char*) {}

    inline void section(const char*) {}

#endif

}
}
}
}
