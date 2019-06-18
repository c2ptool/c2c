#include "util.h"

namespace c2c {

std::string filepath_normalize(const std::string& root, const std::string& file)
{
    if(!file.empty() && file[0]=='/')
        return file;

    std::string res(root);

    if(!res.empty() && res.back()!='/')
        res+="/";

    if(!file.empty())
        return res + file;

    return res;
}

std::string path_normalize(const std::string& root, const std::string& ext)
{
    std::string res;

    if(ext.empty() || ext[0]!='/')
    {
        res = root;

        if(!res.empty() && res.back()!='/')
            res+="/";

        res += ext;
    }
    else
        res = ext;

    if(!res.empty() && res.back()!='/')
        res+="/";

    return res;
}

std::string bin2hex(const std::string& bin)
{
    std::string out;
    std::string hex = "0123456789abcdef";

    for (size_t i = 0; i < bin.size(); i++) {
        out += hex[(bin[i] & 0xF0) >> 4];
        out += hex[bin[i] & 0x0F];
    }
    return out;
}

std::string bin2hex(const unsigned char *bin, size_t sz)
{
    std::string out;
    std::string hex = "0123456789abcdef";

    for (size_t i = 0; i < sz; i++) {
        out += hex[(bin[i] & 0xF0) >> 4];
        out += hex[bin[i] & 0x0F];
    }
    return out;
}

void bin2hex_append(const std::string& bin, std::string& out)
{
    std::string hex = "0123456789abcdef";

    for (size_t i = 0; i < bin.size(); i++) {
        out += hex[(bin[i] & 0xF0) >> 4];
        out += hex[bin[i] & 0x0F];
    }
}

void bin2hex_append(const unsigned char *bin, size_t sz, std::string& out)
{
    std::string hex = "0123456789abcdef";

    for (size_t i = 0; i < sz; i++) {
        out += hex[(bin[i] & 0xF0) >> 4];
        out += hex[bin[i] & 0x0F];
    }
}

template<typename O>
bool __hex2bin__(const std::string& hex, O& bin)
{
    if (hex.size() & 1)
        return false;

    try
    {
        long v = 0;
        for(size_t i = 0; i < (hex.size() + 1) / 2; i++)
        {
            char byte_str[3];
            size_t copied = hex.copy(byte_str, 2, 2 * i);
            byte_str[copied] = char(0);
            char* endptr;
            v = strtoul(byte_str, &endptr, 16);
            if (v < 0 || 0xFF < v || endptr != byte_str + copied)
            {
                return false;
            }
            bin.push_back(static_cast<unsigned char>(v));
        }
        return true;
    }
    catch(...)
    {
        return false;
    }
}

bool hex2bin(const std::string& hex, std::string& bin)
{
    bin.clear();
    return __hex2bin__(hex, bin);
}

bool hex2bin(const std::string& hex, std::vector<unsigned char>& bin)
{
    bin.clear();
    return __hex2bin__(hex, bin);
}

bool hex2bin_append(const std::string& hex, std::string& bin)
{
    return __hex2bin__(hex, bin);
}

bool hex2bin_append(const std::string& hex, std::vector<unsigned char>& bin)
{
    return __hex2bin__(hex, bin);
}


}
