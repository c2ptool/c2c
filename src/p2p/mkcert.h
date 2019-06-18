#ifndef L_MKCERT_H
#define L_MKCERT_H

#include <string>

namespace c2c {

bool mkcert(int bits, long serial_number, long days, std::string& key, std::string& crt, std::string& digest);
bool get_digest_crt(const std::string& crt, std::string& digest);
bool get_digest_crt_file(const std::string& crt, std::string& digest);
const std::string& DH_params();

}

#endif
