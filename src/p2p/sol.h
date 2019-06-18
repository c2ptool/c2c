#ifndef __SOL2_H__
#define __SOL2_H__

#include "lua.hpp"
#include "sol/sol.hpp"
#include "lua_cmsgpack.h"

sol::object json_to_lua(const std::string& s, sol::state_view L, std::string *err = 0);
bool lua_to_json(const sol::object& v, std::string& out);

struct sol_mp_buf
{
    std::string data;
};

namespace sol
{
    template <>
    struct lua_size<sol_mp_buf> : std::integral_constant<int, 1> {};
    template <>
    struct lua_type_of<sol_mp_buf> : std::integral_constant<sol::type, sol::type::poly> {};

    namespace stack
    {
        // return checker
        template <>
        struct checker<sol_mp_buf> {
            template <typename Handler>
            static bool check(lua_State* L, int index, Handler&& handler, record& tracking) {
                return true;
            }
        };

        // return getter
        template <>
        struct getter<sol_mp_buf> {
            static sol_mp_buf get(lua_State* L, int index, record& tracking) {
                sol_mp_buf buf;
                if(tracking.last>0)
                    mp_pack(L, index, index-tracking.last+1, buf.data);
                return buf;
            }
        };

        // return pusher
        template <>
        struct pusher<sol_mp_buf> {
            static int push(lua_State* L, const sol_mp_buf& buf) {
                if(!buf.data.empty())
                    return mp_unpack(L, buf.data.data(), buf.data.size());
                lua_pushnil(L);
                return 1;
            }
        };
    }
}

#endif
