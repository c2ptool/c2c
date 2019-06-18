#ifndef __UTIL_H__
#define __UTIL_H__

#include <string>
#include <vector>

namespace c2c {

std::string filepath_normalize(const std::string& root, const std::string& file = std::string());
std::string path_normalize(const std::string& root, const std::string& ext = std::string());

bool hex2bin(const std::string& hex, std::string& bin);
bool hex2bin(const std::string& hex, std::vector<unsigned char>& bin);

bool hex2bin_append(const std::string& hex, std::string& bin);
bool hex2bin_append(const std::string& hex, std::vector<unsigned char>& bin);

std::string bin2hex(const std::string& bin);
std::string bin2hex(const unsigned char *bin, size_t sz);

}

#endif
