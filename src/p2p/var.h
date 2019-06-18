#ifndef __VAR_H__
#define __VAR_H__

#include "mpark/variant.hpp"

#include <string>
#include <vector>
#include <map>

namespace c2c {

typedef enum {
    NIL = 0,
    BOOL,
    INT8,
    UINT8,
    INT16,
    UINT16,
    INT32,
    UINT32,
    INT64,
    UINT64,
    FLOAT,
    DOUBLE,
    STRING,
    BINARY,
    MAP,
    VEC
} var_type_t;

struct item_t;

typedef void* nil_t;
typedef std::vector<uint8_t> binary_t;
typedef std::shared_ptr<std::map<std::string, item_t>> map_t;
typedef std::shared_ptr<std::vector<item_t>> vec_t;

typedef mpark::variant<
    nil_t,
    bool,
    int8_t,
    int16_t,
    int32_t,
    int64_t,
    uint8_t,
    uint16_t,
    uint32_t,
    uint64_t,
    float,
    double,
    std::string,
    binary_t,
    map_t,
    vec_t
> var_t;

struct item_t
{
    var_t value;
};

var_type_t type(const var_t& var);

int cmp(const var_t& v1, const var_t& v2);
int cmp(const vec_t& a1, const vec_t& a2);

inline bool operator < (const var_t& v1, const var_t& v2) { return 0 < cmp(v1, v2); }
inline bool operator > (const var_t& v1, const var_t& v2) { return 0 > cmp(v1, v2); }
inline bool operator <= (const var_t& v1, const var_t& v2) { return 0 <= cmp(v1, v2); }
inline bool operator >= (const var_t& v1, const var_t& v2) { return 0 >= cmp(v1, v2); }
inline bool operator == (const var_t& v1, const var_t& v2) { return 0 == cmp(v1, v2); }
inline bool operator != (const var_t& v1, const var_t& v2) { return 0 != cmp(v1, v2); }

inline bool operator < (const vec_t& v1, const vec_t& v2) { return 0 < cmp(v1, v2); }
inline bool operator > (const vec_t& v1, const vec_t& v2) { return 0 > cmp(v1, v2); }
inline bool operator <= (const vec_t& v1, const vec_t& v2) { return 0 <= cmp(v1, v2); }
inline bool operator >= (const vec_t& v1, const vec_t& v2) { return 0 >= cmp(v1, v2); }
inline bool operator == (const vec_t& v1, const vec_t& v2) { return 0 == cmp(v1, v2); }
inline bool operator != (const vec_t& v1, const vec_t& v2) { return 0 != cmp(v1, v2); }

}

#endif
