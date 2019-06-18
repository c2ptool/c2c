#ifndef L_FUNC_H
#define L_FUNC_H

#include "conn.h"

namespace c2c {

typedef std::function<bool(connection_ptr /*con*/, const std::string& /*method*/, var_t /*params*/)> call_t;
typedef std::function<bool(connection_ptr /*con*/, const std::string& /*method*/, var_t /*params*/, call_t /*reply*/)> call_r_t;
typedef std::function<bool(connection_ptr /*con*/, var_t /*params*/)> func_t;
typedef std::function<bool(connection_ptr /*con*/, var_t /*params*/, call_t /*reply*/)> func_r_t;
typedef std::function<void(connection_ptr /*con*/)> on_connection_t;


template<typename A1>
var_t to_var(A1 a1)
{
    var_t r = a1;
    return r;
}

template<typename A1, typename A2>
var_t to_var(A1 a1, A2 a2)
{
    var_t r = std::make_shared<std::vector<item_t>>();
    vec_t vec = mpark::get<vec_t>(r);
    vec->resize(2);
    (*vec)[0].value = a1;
    (*vec)[1].value = a2;
    return r;
}

template<typename A1, typename A2, typename A3>
var_t to_var(A1 a1, A2 a2, A3 a3)
{
    var_t r = std::make_shared<std::vector<item_t>>();
    vec_t vec = mpark::get<vec_t>(r);
    vec->resize(3);
    (*vec)[0].value = a1;
    (*vec)[1].value = a2;
    (*vec)[2].value = a3;
    return r;
}

template<typename A1, typename A2, typename A3, typename A4>
var_t to_var(A1 a1, A2 a2, A3 a3, A4 a4)
{
    var_t r = std::make_shared<std::vector<item_t>>();
    vec_t vec = mpark::get<vec_t>(r);
    vec->resize(4);
    (*vec)[0].value = a1;
    (*vec)[1].value = a2;
    (*vec)[2].value = a3;
    (*vec)[3].value = a4;
    return r;
}

template<typename A1, typename A2, typename A3, typename A4, typename A5>
var_t to_var(A1 a1, A2 a2, A3 a3, A4 a4, A5 a5)
{
    var_t r = std::make_shared<std::vector<item_t>>();
    vec_t vec = mpark::get<vec_t>(r);
    vec->resize(5);
    (*vec)[0].value = a1;
    (*vec)[1].value = a2;
    (*vec)[2].value = a3;
    (*vec)[3].value = a4;
    (*vec)[4].value = a5;
    return r;
}

template<typename A1, typename A2, typename A3, typename A4, typename A5, typename A6>
var_t to_var(A1 a1, A2 a2, A3 a3, A4 a4, A5 a5, A6 a6)
{
    var_t r = std::make_shared<std::vector<item_t>>();
    vec_t vec = mpark::get<vec_t>(r);
    vec->resize(6);
    (*vec)[0].value = a1;
    (*vec)[1].value = a2;
    (*vec)[2].value = a3;
    (*vec)[3].value = a4;
    (*vec)[4].value = a5;
    (*vec)[5].value = a6;
    return r;
}

template<typename A1, typename A2, typename A3, typename A4, typename A5, typename A6, typename A7>
var_t to_var(A1 a1, A2 a2, A3 a3, A4 a4, A5 a5, A6 a6, A7 a7)
{
    var_t r = std::make_shared<std::vector<item_t>>();
    vec_t vec = mpark::get<vec_t>(r);
    vec->resize(7);
    (*vec)[0].value = a1;
    (*vec)[1].value = a2;
    (*vec)[2].value = a3;
    (*vec)[3].value = a4;
    (*vec)[4].value = a5;
    (*vec)[5].value = a6;
    (*vec)[6].value = a7;
    return r;
}

template<typename A1, typename A2, typename A3, typename A4, typename A5, typename A6, typename A7, typename A8>
var_t to_var(A1 a1, A2 a2, A3 a3, A4 a4, A5 a5, A6 a6, A7 a7, A8 a8)
{
    var_t r = std::make_shared<std::vector<item_t>>();
    vec_t vec = mpark::get<vec_t>(r);
    vec->resize(8);
    (*vec)[0].value = a1;
    (*vec)[1].value = a2;
    (*vec)[2].value = a3;
    (*vec)[3].value = a4;
    (*vec)[4].value = a5;
    (*vec)[5].value = a6;
    (*vec)[6].value = a7;
    (*vec)[7].value = a8;
    return r;
}

template<typename A1, typename A2, typename A3, typename A4, typename A5, typename A6, typename A7, typename A8, typename A9>
var_t to_var(A1 a1, A2 a2, A3 a3, A4 a4, A5 a5, A6 a6, A7 a7, A8 a8, A9 a9)
{
    var_t r = std::make_shared<std::vector<item_t>>();
    vec_t vec = mpark::get<vec_t>(r);
    vec->resize(9);
    (*vec)[0].value = a1;
    (*vec)[1].value = a2;
    (*vec)[2].value = a3;
    (*vec)[3].value = a4;
    (*vec)[4].value = a5;
    (*vec)[5].value = a6;
    (*vec)[6].value = a7;
    (*vec)[7].value = a8;
    (*vec)[8].value = a9;
    return r;
}

template<typename A1, typename A2, typename A3, typename A4, typename A5, typename A6, typename A7, typename A8, typename A9, typename A10>
var_t to_var(A1 a1, A2 a2, A3 a3, A4 a4, A5 a5, A6 a6, A7 a7, A8 a8, A9 a9, A10 a10)
{
    var_t r = std::make_shared<std::vector<item_t>>();
    vec_t vec = mpark::get<vec_t>(r);
    vec->resize(10);
    (*vec)[0].value = a1;
    (*vec)[1].value = a2;
    (*vec)[2].value = a3;
    (*vec)[3].value = a4;
    (*vec)[4].value = a5;
    (*vec)[5].value = a6;
    (*vec)[6].value = a7;
    (*vec)[7].value = a8;
    (*vec)[8].value = a9;
    (*vec)[9].value = a10;
    return r;
}

class response_t
{
    connection_ptr c_;
    call_t f_;
public:
    response_t(connection_ptr c, call_t f) : c_(c), f_(f) {}
    template<typename... A>
    void operator ()(const A&... args)
    {
        var_t pars = to_var(args...);
        f_(c_, "result", pars);
    }
    template<typename... A>
    void error(const A&... args)
    {
        var_t pars = to_var(args...);
        f_(c_, "error", pars);
    }
};

template<typename T, typename A1>
func_t wrap(void(T::*f)(connection_ptr, A1), T *p)
{
    auto F = std::bind(f, p, std::placeholders::_1, std::placeholders::_2);
    return [F](connection_ptr con, var_t par) -> bool {
        A1& a1 = mpark::get<A1>(par);
        F(con, a1);
        return true;
    };
}

template<typename T, typename A1>
func_r_t wrap_r(void(T::*f)(connection_ptr, A1, response_t), T *p)
{
    auto F = std::bind(f, p, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3);
    return [F](connection_ptr con, var_t pars, call_t r) -> bool {
        A1& a1 = mpark::get<A1>(pars);
        F(con, a1);
        F(con, a1, response_t(con, r));
        return true;
    };
}

template<typename T, typename A1, typename A2>
func_t wrap(void(T::*f)(connection_ptr, A1, A2), T *p)
{
    auto F = std::bind(f, p, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3);
    return [F](connection_ptr con, var_t pars) -> bool {
        vec_t& vec = mpark::get<vec_t>(pars);
        if(vec->size() != 2)
            throw std::runtime_error("error count of parameters");
        A1& a1 = mpark::get<A1>((*vec)[0].value);
        A2& a2 = mpark::get<A2>((*vec)[1].value);
        F(con, a1, a2);
        return true;
    };
}

template<typename T, typename A1, typename A2>
func_r_t wrap_r(void(T::*f)(connection_ptr, A1, A2, response_t), T *p)
{
    auto F = std::bind(f, p, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4);
    return [F](connection_ptr con, var_t pars, call_t r) -> bool {
        vec_t& vec = mpark::get<vec_t>(pars);
        if(vec->size() != 2)
            throw std::runtime_error("error count of parameters");
        A1& a1 = mpark::get<A1>((*vec)[0].value);
        A2& a2 = mpark::get<A2>((*vec)[1].value);
        F(con, a1, a2, response_t(con, r));
        return true;
    };
}

template<typename T, typename A1, typename A2, typename A3>
func_t wrap(void(T::*f)(connection_ptr, A1, A2, A3), T *p)
{
    auto F = std::bind(f, p, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4);
    return [F](connection_ptr con, var_t pars) {
        vec_t& vec = mpark::get<vec_t>(pars);
        if(vec->size() != 3)
            throw std::runtime_error("error count of parameters");
        A1& a1 = mpark::get<A1>((*vec)[0].value);
        A2& a2 = mpark::get<A2>((*vec)[1].value);
        A3& a3 = mpark::get<A3>((*vec)[2].value);
        F(con, a1, a2, a3);
        return true;
    };
}

template<typename T, typename A1, typename A2, typename A3>
func_r_t wrap_r(void(T::*f)(connection_ptr, A1, A2, A3, response_t), T *p)
{
    auto F = std::bind(f, p, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5);
    return [F](connection_ptr con, var_t pars, call_t r) {
        vec_t& vec = mpark::get<vec_t>(pars);
        if(vec->size() != 3)
            throw std::runtime_error("error count of parameters");
        A1& a1 = mpark::get<A1>((*vec)[0].value);
        A2& a2 = mpark::get<A2>((*vec)[1].value);
        A3& a3 = mpark::get<A3>((*vec)[2].value);
        F(con, a1, a2, a3, response_t(con, r));
        return true;
    };
}

template<typename T, typename A1, typename A2, typename A3, typename A4>
func_t wrap(void(T::*f)(connection_ptr, A1, A2, A3, A4), T *p)
{
    auto F = std::bind(f, p, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5);
    return [F](connection_ptr con, var_t pars) -> bool {
        vec_t& vec = mpark::get<vec_t>(pars);
        if(vec->size() != 4)
            throw std::runtime_error("error count of parameters");
        A1& a1 = mpark::get<A1>((*vec)[0].value);
        A2& a2 = mpark::get<A2>((*vec)[1].value);
        A3& a3 = mpark::get<A3>((*vec)[2].value);
        A4& a4 = mpark::get<A4>((*vec)[3].value);
        F(con, a1, a2, a3, a4);
        return true;
    };
}

template<typename T, typename A1, typename A2, typename A3, typename A4>
func_r_t wrap_r(void(T::*f)(connection_ptr, A1, A2, A3, A4, response_t), T *p)
{
    auto F = std::bind(f, p, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5, std::placeholders::_6);
    return [F](connection_ptr con, var_t pars, call_t r) -> bool {
        vec_t& vec = mpark::get<vec_t>(pars);
        if(vec->size() != 4)
            throw std::runtime_error("error count of parameters");
        A1& a1 = mpark::get<A1>((*vec)[0].value);
        A2& a2 = mpark::get<A2>((*vec)[1].value);
        A3& a3 = mpark::get<A3>((*vec)[2].value);
        A4& a4 = mpark::get<A4>((*vec)[3].value);
        F(con, a1, a2, a3, a4, response_t(con, r));
        return true;
    };
}

template<typename T, typename A1, typename A2, typename A3, typename A4, typename A5>
func_t wrap(void(T::*f)(connection_ptr, A1, A2, A3, A4, A5), T *p)
{
    auto F = std::bind(f, p, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5, std::placeholders::_6);
    return [F](connection_ptr con, var_t pars) -> bool {
        vec_t& vec = mpark::get<vec_t>(pars);
        if(vec->size() != 5)
            throw std::runtime_error("error count of parameters");
        A1& a1 = mpark::get<A1>((*vec)[0].value);
        A2& a2 = mpark::get<A2>((*vec)[1].value);
        A3& a3 = mpark::get<A3>((*vec)[2].value);
        A4& a4 = mpark::get<A4>((*vec)[3].value);
        A5& a5 = mpark::get<A5>((*vec)[4].value);
        F(con, a1, a2, a3, a4, a5);
        return true;
    };
}

template<typename T, typename A1, typename A2, typename A3, typename A4, typename A5>
func_r_t wrap_r(void(T::*f)(connection_ptr, A1, A2, A3, A4, A5, response_t), T *p)
{
    auto F = std::bind(f, p, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5, std::placeholders::_6, std::placeholders::_7);
    return [F](connection_ptr con, var_t pars, call_t r) -> bool {
        vec_t& vec = mpark::get<vec_t>(pars);
        if(vec->size() != 5)
            throw std::runtime_error("error count of parameters");
        A1& a1 = mpark::get<A1>((*vec)[0].value);
        A2& a2 = mpark::get<A2>((*vec)[1].value);
        A3& a3 = mpark::get<A3>((*vec)[2].value);
        A4& a4 = mpark::get<A4>((*vec)[3].value);
        A5& a5 = mpark::get<A5>((*vec)[4].value);
        F(con, a1, a2, a3, a4, a5, response_t(con, r));
        return true;
    };
}

template<typename T, typename A1, typename A2, typename A3, typename A4, typename A5, typename A6>
func_t wrap(void(T::*f)(connection_ptr, A1, A2, A3, A4, A5, A6), T *p)
{
    auto F = std::bind(f, p, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5, std::placeholders::_6, std::placeholders::_7);
    return [F](connection_ptr con, var_t pars) -> bool {
        vec_t& vec = mpark::get<vec_t>(pars);
        if(vec->size() != 6)
            throw std::runtime_error("error count of parameters");
        A1& a1 = mpark::get<A1>((*vec)[0].value);
        A2& a2 = mpark::get<A2>((*vec)[1].value);
        A3& a3 = mpark::get<A3>((*vec)[2].value);
        A4& a4 = mpark::get<A4>((*vec)[3].value);
        A5& a5 = mpark::get<A5>((*vec)[4].value);
        A6& a6 = mpark::get<A6>((*vec)[5].value);
        F(con, a1, a2, a3, a4, a5, a6);
        return true;
    };
}

template<typename T, typename A1, typename A2, typename A3, typename A4, typename A5, typename A6>
func_r_t wrap_r(void(T::*f)(connection_ptr, A1, A2, A3, A4, A5, A6, response_t), T *p)
{
    auto F = std::bind(f, p, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5, std::placeholders::_6, std::placeholders::_7, std::placeholders::_8);
    return [F](connection_ptr con, var_t pars, call_t r) -> bool {
        vec_t& vec = mpark::get<vec_t>(pars);
        if(vec->size() != 6)
            throw std::runtime_error("error count of parameters");
        A1& a1 = mpark::get<A1>((*vec)[0].value);
        A2& a2 = mpark::get<A2>((*vec)[1].value);
        A3& a3 = mpark::get<A3>((*vec)[2].value);
        A4& a4 = mpark::get<A4>((*vec)[3].value);
        A5& a5 = mpark::get<A5>((*vec)[4].value);
        A6& a6 = mpark::get<A6>((*vec)[5].value);
        F(con, a1, a2, a3, a4, a5, a6, response_t(con, r));
        return true;
    };
}

template<typename T, typename A1, typename A2, typename A3, typename A4, typename A5, typename A6, typename A7>
func_t wrap(void(T::*f)(connection_ptr, A1, A2, A3, A4, A5, A6, A7), T *p)
{
    auto F = std::bind(f, p, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5, std::placeholders::_6, std::placeholders::_7, std::placeholders::_8);
    return [F](connection_ptr con, var_t pars) -> bool {
        vec_t& vec = mpark::get<vec_t>(pars);
        if(vec->size() != 7)
            throw std::runtime_error("error count of parameters");
        A1& a1 = mpark::get<A1>((*vec)[0].value);
        A2& a2 = mpark::get<A2>((*vec)[1].value);
        A3& a3 = mpark::get<A3>((*vec)[2].value);
        A4& a4 = mpark::get<A4>((*vec)[3].value);
        A5& a5 = mpark::get<A5>((*vec)[4].value);
        A6& a6 = mpark::get<A6>((*vec)[5].value);
        A7& a7 = mpark::get<A7>((*vec)[6].value);
        F(con, a1, a2, a3, a4, a5, a6, a7);
        return true;
    };
}

template<typename T, typename A1, typename A2, typename A3, typename A4, typename A5, typename A6, typename A7>
func_r_t wrap_r(void(T::*f)(connection_ptr, A1, A2, A3, A4, A5, A6, A7, response_t), T *p)
{
    auto F = std::bind(f, p, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5, std::placeholders::_6, std::placeholders::_7, std::placeholders::_8, std::placeholders::_9);
    return [F](connection_ptr con, var_t pars, call_t r) -> bool {
        vec_t& vec = mpark::get<vec_t>(pars);
        if(vec->size() != 7)
            throw std::runtime_error("error count of parameters");
        A1& a1 = mpark::get<A1>((*vec)[0].value);
        A2& a2 = mpark::get<A2>((*vec)[1].value);
        A3& a3 = mpark::get<A3>((*vec)[2].value);
        A4& a4 = mpark::get<A4>((*vec)[3].value);
        A5& a5 = mpark::get<A5>((*vec)[4].value);
        A6& a6 = mpark::get<A6>((*vec)[5].value);
        A7& a7 = mpark::get<A7>((*vec)[6].value);
        F(con, a1, a2, a3, a4, a5, a6, a7, response_t(con, r));
        return true;
    };
}

template<typename T, typename A1, typename A2, typename A3, typename A4, typename A5, typename A6, typename A7, typename A8>
func_t wrap(void(T::*f)(connection_ptr, A1, A2, A3, A4, A5, A6, A7, A8), T *p)
{
    auto F = std::bind(f, p, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5, std::placeholders::_6, std::placeholders::_7, std::placeholders::_8, std::placeholders::_9);
    return [F](connection_ptr con, var_t pars) -> bool {
        vec_t& vec = mpark::get<vec_t>(pars);
        if(vec->size() != 8)
            throw std::runtime_error("error count of parameters");
        A1& a1 = mpark::get<A1>((*vec)[0].value);
        A2& a2 = mpark::get<A2>((*vec)[1].value);
        A3& a3 = mpark::get<A3>((*vec)[2].value);
        A4& a4 = mpark::get<A4>((*vec)[3].value);
        A5& a5 = mpark::get<A5>((*vec)[4].value);
        A6& a6 = mpark::get<A6>((*vec)[5].value);
        A7& a7 = mpark::get<A7>((*vec)[6].value);
        A8& a8 = mpark::get<A8>((*vec)[7].value);
        F(con, a1, a2, a3, a4, a5, a6, a7, a8);
        return true;
    };
}

template<typename T, typename A1, typename A2, typename A3, typename A4, typename A5, typename A6, typename A7, typename A8>
func_r_t wrap_r(void(T::*f)(connection_ptr, A1, A2, A3, A4, A5, A6, A7, A8, response_t), T *p)
{
    auto F = std::bind(f, p, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5, std::placeholders::_6, std::placeholders::_7, std::placeholders::_8, std::placeholders::_9, std::placeholders::_10);
    return [F](connection_ptr con, var_t pars, call_t r) -> bool {
        vec_t& vec = mpark::get<vec_t>(pars);
        if(vec->size() != 8)
            throw std::runtime_error("error count of parameters");
        A1& a1 = mpark::get<A1>((*vec)[0].value);
        A2& a2 = mpark::get<A2>((*vec)[1].value);
        A3& a3 = mpark::get<A3>((*vec)[2].value);
        A4& a4 = mpark::get<A4>((*vec)[3].value);
        A5& a5 = mpark::get<A5>((*vec)[4].value);
        A6& a6 = mpark::get<A6>((*vec)[5].value);
        A7& a7 = mpark::get<A7>((*vec)[6].value);
        A8& a8 = mpark::get<A8>((*vec)[7].value);
        F(con, a1, a2, a3, a4, a5, a6, a7, a8, response_t(con, r));
        return true;
    };
}

template<typename T, typename A1, typename A2, typename A3, typename A4, typename A5, typename A6, typename A7, typename A8, typename A9>
func_t wrap(void(T::*f)(connection_ptr, A1, A2, A3, A4, A5, A6, A7, A8, A9), T *p)
{
    auto F = std::bind(f, p, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5, std::placeholders::_6, std::placeholders::_7, std::placeholders::_8, std::placeholders::_9, std::placeholders::_10);
    return [F](connection_ptr con, var_t pars) -> bool {
        vec_t& vec = mpark::get<vec_t>(pars);
        if(vec->size() != 9)
            throw std::runtime_error("error count of parameters");
        A1& a1 = mpark::get<A1>((*vec)[0].value);
        A2& a2 = mpark::get<A2>((*vec)[1].value);
        A3& a3 = mpark::get<A3>((*vec)[2].value);
        A4& a4 = mpark::get<A4>((*vec)[3].value);
        A5& a5 = mpark::get<A5>((*vec)[4].value);
        A6& a6 = mpark::get<A6>((*vec)[5].value);
        A7& a7 = mpark::get<A7>((*vec)[6].value);
        A8& a8 = mpark::get<A8>((*vec)[7].value);
        A9& a9 = mpark::get<A9>((*vec)[8].value);
        F(con, a1, a2, a3, a4, a5, a6, a7, a8, a9);
        return true;
    };
}

template<typename T, typename A1, typename A2, typename A3, typename A4, typename A5, typename A6, typename A7, typename A8, typename A9>
func_r_t wrap_r(void(T::*f)(connection_ptr, A1, A2, A3, A4, A5, A6, A7, A8, A9, response_t), T *p)
{
    auto F = std::bind(f, p, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5, std::placeholders::_6, std::placeholders::_7, std::placeholders::_8, std::placeholders::_9, std::placeholders::_10, std::placeholders::_11);
    return [F](connection_ptr con, var_t pars, call_t r) -> bool {
        vec_t& vec = mpark::get<vec_t>(pars);
        if(vec->size() != 9)
            throw std::runtime_error("error count of parameters");
        A1& a1 = mpark::get<A1>((*vec)[0].value);
        A2& a2 = mpark::get<A2>((*vec)[1].value);
        A3& a3 = mpark::get<A3>((*vec)[2].value);
        A4& a4 = mpark::get<A4>((*vec)[3].value);
        A5& a5 = mpark::get<A5>((*vec)[4].value);
        A6& a6 = mpark::get<A6>((*vec)[5].value);
        A7& a7 = mpark::get<A7>((*vec)[6].value);
        A8& a8 = mpark::get<A8>((*vec)[7].value);
        A9& a9 = mpark::get<A9>((*vec)[8].value);
        F(con, a1, a2, a3, a4, a5, a6, a7, a8, a9, response_t(con, r));
        return true;
    };
}

template<typename T, typename A1, typename A2, typename A3, typename A4, typename A5, typename A6, typename A7, typename A8, typename A9, typename A10>
func_t wrap(void(T::*f)(connection_ptr, A1, A2, A3, A4, A5, A6, A7, A8, A9, A10), T *p)
{
    auto F = std::bind(f, p, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5, std::placeholders::_6, std::placeholders::_7, std::placeholders::_8, std::placeholders::_9, std::placeholders::_10, std::placeholders::_11);
    return [F](connection_ptr con, var_t pars) -> bool {
        vec_t& vec = mpark::get<vec_t>(pars);
        if(vec->size() != 10)
            throw std::runtime_error("error count of parameters");
        A1& a1 = mpark::get<A1>((*vec)[0].value);
        A2& a2 = mpark::get<A2>((*vec)[1].value);
        A3& a3 = mpark::get<A3>((*vec)[2].value);
        A4& a4 = mpark::get<A4>((*vec)[3].value);
        A5& a5 = mpark::get<A5>((*vec)[4].value);
        A6& a6 = mpark::get<A6>((*vec)[5].value);
        A7& a7 = mpark::get<A7>((*vec)[6].value);
        A8& a8 = mpark::get<A8>((*vec)[7].value);
        A9& a9 = mpark::get<A9>((*vec)[8].value);
        A10& a10 = mpark::get<A10>((*vec)[9].value);
        F(con, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10);
        return true;
    };
}

template<typename T, typename A1, typename A2, typename A3, typename A4, typename A5, typename A6, typename A7, typename A8, typename A9, typename A10>
func_r_t wrap_r(void(T::*f)(connection_ptr, A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, response_t), T *p)
{
    auto F = std::bind(f, p, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5, std::placeholders::_6, std::placeholders::_7, std::placeholders::_8, std::placeholders::_9, std::placeholders::_10, std::placeholders::_11, std::placeholders::_12);
    return [F](connection_ptr con, var_t pars, call_t r) -> bool {
        vec_t& vec = mpark::get<vec_t>(pars);
        if(vec->size() != 10)
            throw std::runtime_error("error count of parameters");
        A1& a1 = mpark::get<A1>((*vec)[0].value);
        A2& a2 = mpark::get<A2>((*vec)[1].value);
        A3& a3 = mpark::get<A3>((*vec)[2].value);
        A4& a4 = mpark::get<A4>((*vec)[3].value);
        A5& a5 = mpark::get<A5>((*vec)[4].value);
        A6& a6 = mpark::get<A6>((*vec)[5].value);
        A7& a7 = mpark::get<A7>((*vec)[6].value);
        A8& a8 = mpark::get<A8>((*vec)[7].value);
        A9& a9 = mpark::get<A9>((*vec)[8].value);
        A10& a10 = mpark::get<A10>((*vec)[9].value);
        F(con, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, response_t(con, r));
        return true;
    };
}

}

#endif
