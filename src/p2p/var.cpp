#include "var.h"
#include <math.h>
#include <cstdint>

namespace c2c {

var_type_t type(const var_t& var)
{
    struct visitor
    {
        var_type_t operator()(nil_t) const { return NIL; }
        var_type_t operator()(bool) const { return BOOL; }
        var_type_t operator()(int8_t) const { return INT8; }
        var_type_t operator()(int16_t) const { return INT16; }
        var_type_t operator()(int32_t) const { return INT32; }
        var_type_t operator()(int64_t) const { return INT64; }
        var_type_t operator()(uint8_t) const { return UINT8; }
        var_type_t operator()(uint16_t) const { return UINT16; }
        var_type_t operator()(uint32_t) const { return UINT32; }
        var_type_t operator()(uint64_t) const { return UINT64; }
        var_type_t operator()(float) const { return FLOAT;  }
        var_type_t operator()(double) const { return DOUBLE; }
        var_type_t operator()(const std::string&) const { return STRING; }
        var_type_t operator()(const binary_t&) const { return BINARY; }
        var_type_t operator()(const map_t&) const { return MAP; }
        var_type_t operator()(const vec_t&) const { return VEC; }
    };
    visitor v;
    return mpark::visit(v, var);
}

struct to_int64
{
    int64_t val;
    bool operator()(nil_t) { return false; }
    bool operator()(bool) { return false; }
    bool operator()(int8_t v) { val = v; return true; }
    bool operator()(int16_t v) { val = v; return true; }
    bool operator()(int32_t v) { val = v; return true; }
    bool operator()(int64_t v) { val = v; return true; }
    bool operator()(uint8_t v) { val = v; return true; }
    bool operator()(uint16_t v) { val = v; return true; }
    bool operator()(uint32_t v) { val = v; return true; }
    bool operator()(uint64_t v) { if(v > INTMAX_MAX) return false; val = int64_t(v); return true; }
    bool operator()(float v) { val = int64_t(floor(v)); return true; }
    bool operator()(double v) { val = int64_t(floor(v)); return true; }
    bool operator()(const std::string&) { return false; }
    bool operator()(const binary_t&) { return false; }
    bool operator()(const map_t&) { return false; }
    bool operator()(const vec_t&) { return false; }
};

struct to_uint64
{
    uint64_t val;
    bool operator()(nil_t) { return false; }
    bool operator()(bool) { return false; }
    bool operator()(int8_t v) { if(v < 0) return false; val = uint64_t(v); return true; }
    bool operator()(int16_t v) { if(v < 0) return false; val = uint64_t(v); return true; }
    bool operator()(int32_t v) { if(v < 0) return false; val = uint64_t(v); return true; }
    bool operator()(int64_t v) { if(v < 0) return false; val = uint64_t(v); return true; }
    bool operator()(uint8_t v) { val = v; return true; }
    bool operator()(uint16_t v) { val = v; return true; }
    bool operator()(uint32_t v) { val = v; return true; }
    bool operator()(uint64_t v) { val = v; return true; }
    bool operator()(float v) { if(v < 0) return false; val = uint64_t(floor(v)); return true; }
    bool operator()(double v) { if(v < 0) return false; val = uint64_t(floor(v)); return true; }
    bool operator()(const std::string&) { return false; }
    bool operator()(const binary_t&) { return false; }
    bool operator()(const map_t&) { return false; }
    bool operator()(const vec_t&) { return false; }
};

struct to_double
{
    double val;
    bool operator()(nil_t) { return false; }
    bool operator()(bool) { return false; }
    bool operator()(int8_t v) { val = double(v); return true; }
    bool operator()(int16_t v) { val = double(v); return true; }
    bool operator()(int32_t v) { val = double(v); return true; }
    bool operator()(int64_t v) { val = double(v); return true; }
    bool operator()(uint8_t v) { val = double(v); return true; }
    bool operator()(uint16_t v) { val = double(v); return true; }
    bool operator()(uint32_t v) { val = double(v); return true; }
    bool operator()(uint64_t v) { val = double(v); return true; }
    bool operator()(float v) { val = double(v); return true; }
    bool operator()(double v) { val = v; return true; }
    bool operator()(const std::string&) { return false; }
    bool operator()(const binary_t&) { return false; }
    bool operator()(const map_t&) { return false; }
    bool operator()(const vec_t&) { return false; }
};

int cmp(const var_t& v1, const var_t& v2)
{
    var_type_t t1 = type(v1);
    var_type_t t2 = type(v2);

    if(t1 >= INT8 && t1 <= DOUBLE && t2 >= INT8 && t2 <= DOUBLE)
    {
        to_int64 I1;
        if(!mpark::visit(I1, v1))
        {
            to_uint64 U1; mpark::visit(U1, v1);
            to_uint64 U2;
            if(!mpark::visit(U2, v2))
                return 1;
            return U1.val < U2.val ? -1 : (U1.val > U2.val ? 1 : 0);
        }
        else if(t2 >= INT8 && t2 <= DOUBLE)
        {
            to_int64 I2;
            if(!mpark::visit(I2, v2))
                return -1;
            return I1.val < I2.val ? -1 : (I1.val > I2.val ? 1 : 0);
        }
    }

    if(t1 == STRING && t2 == STRING)
    {
        const std::string& s1 = mpark::get<std::string>(v1);
        const std::string& s2 = mpark::get<std::string>(v2);
        return s1 < s2 ? -1 : (s1 > s2 ? 1 : 0);
    }

    if(t1 == BINARY && t2 == BINARY)
    {
        const binary_t& b1 = mpark::get<binary_t>(v1);
        const binary_t& b2 = mpark::get<binary_t>(v2);
        return b1 < b2 ? -1 : (b1 > b2 ? 1 : 0);
    }

    if(t1 == VEC && t2 == VEC)
        return cmp(mpark::get<vec_t>(v1), mpark::get<vec_t>(v2));

    return t1 < t2 ? -1 : (t1 > t2 ? 1 : 0);
}

int cmp(const vec_t& a1, const vec_t& a2)
{
    if(a1->size() < a2->size())
        return -1;
    if(a1->size() > a2->size())
        return 1;
    for(size_t n=0; n<a1->size(); n++)
    {
        int rc = cmp(a1->at(n).value, a2->at(n).value);
        if(rc != 0)
            return rc;
    }
    return 0;
}

}
