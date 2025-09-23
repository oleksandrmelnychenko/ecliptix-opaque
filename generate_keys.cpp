#include <sodium.h>
#include <iostream>
#include <iomanip>
#include <cstdint>

void print_hex_array(const char* name, const uint8_t* data, size_t len) {
    std::cout << "constexpr uint8_t " << name << "[" << len << "] = {" << std::endl << "    ";
    for (size_t i = 0; i < len; ++i) {
        std::cout << "0x" << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<unsigned>(data[i]);
        if (i < len - 1) std::cout << ", ";
        if ((i + 1) % 8 == 0 && i < len - 1) std::cout << std::endl << "    ";
    }
    std::cout << std::endl << "};" << std::endl << std::endl;
}

int main() {
    if (sodium_init() < 0) {
        std::cerr << "Failed to initialize libsodium" << std::endl;
        return 1;
    }

    uint8_t private_key[32];
    uint8_t public_key[32];

    crypto_core_ristretto255_scalar_random(private_key);

    if (crypto_scalarmult_ristretto255_base(public_key, private_key) != 0) {
        std::cerr << "Failed to generate public key" << std::endl;
        return 1;
    }

    std::cout << "// OPAQUE Server Keypair (ristretto255)" << std::endl;
    std::cout << "// Generated using libsodium crypto_core_ristretto255" << std::endl;
    std::cout << "namespace ecliptix::security::opaque::keys {" << std::endl << std::endl;

    print_hex_array("SERVER_PRIVATE_KEY", private_key, 32);
    print_hex_array("SERVER_PUBLIC_KEY", public_key, 32);

    std::cout << "} // namespace ecliptix::security::opaque::keys" << std::endl;

    return 0;
}