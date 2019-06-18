#ifndef __MKCERT_H__
#define __MKCERT_H__

#include <string>

bool mkcert(int bits, long sn, long days, std::string& sk, std::string& cert, std::string& digest);

#endif
