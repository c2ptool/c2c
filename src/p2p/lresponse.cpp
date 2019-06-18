#include "lresponse.h"
#include "msg.h"

namespace c2c {
    namespace lua {

    response::response(const std::shared_ptr<worker::server>& w, call_t r)
        : w_(w), r_(r)
    {
    }

    void response::reply(sol::variadic_args args)
    {
        vec_t pars;
        if(args.size()>0)
            pars = lua2vec(args.lua_state(), args.stack_index(), args.top());
        r_(connection_ptr(), "result", pars);
    }

    bool response::reg(sol::state_view& lua)
    {
        lua.new_usertype<response>("lua.response",
            sol::meta_function::call, &response::reply);
        return true;
    }

}}
