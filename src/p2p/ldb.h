#ifndef L_DB_LUA_H
#define L_DB_LUA_H

#include "lua.hpp"

namespace c2c {
    struct mpack_param;
    struct var_param;
    struct vec_param;
}

namespace sol {
    namespace stack {
        // arguments pusher
        int push(lua_State*, c2c::mpack_param*);
        int push(lua_State*, c2c::var_param*);
        int push(lua_State*, c2c::vec_param*);
    }
}

#include "sol.h"
#include "db.h"
#include "func.h"
#include "var.h"

#include <set>

namespace c2c {

struct mpack_param { const char *p; size_t sz; };
struct var_param { var_t v; };
struct vec_param { vec_t v; };

class script;

class ldb : public  std::enable_shared_from_this<ldb>
{
public:
    struct pairs_t {
        pairs_t(ldb *p, const char *key, size_t sz)
            : self(std::make_shared<ldb>(p, key, sz)) {}
        static int iterator(lua_State* L);
        std::shared_ptr<ldb> self;
    };
    struct rpairs_t {
        rpairs_t(ldb *p, const char *key, size_t sz)
            : self(std::make_shared<ldb>(p, key, sz)) {}
        static int iterator(lua_State* L);
        std::shared_ptr<ldb> self;
    };

private:
    std::weak_ptr<script> s_;
    db_layer<DB_DATA_LAYER> db_;
    std::string name_;
    size_t postfix_len_;
    std::vector<connection_ptr> peers_;
public:
    ldb(const std::shared_ptr<script>& s, const std::string& name);
    ldb(const std::shared_ptr<script>& s, const std::string& name, const char *pfx, size_t sz);
    ldb(const std::shared_ptr<script>& s, const std::string& name, const std::string& pfx);

    ldb(ldb *self);
    ldb(ldb *self, const char *pfx, size_t sz);

    const std::string& get_name();

    sol::object getter(sol::stack_object key, sol::this_state L);
    void setter(sol::stack_object key, sol::stack_object value, sol::this_state);

    sol::object at(sol::variadic_args args);

    sol_mp_buf get(sol::variadic_args args);
    void put(sol::variadic_args args);
    void del(sol::variadic_args args);

    void begin();
    void commit();

    sol_mp_buf seek(sol::variadic_args args);
    sol_mp_buf skip(int n);
    sol_mp_buf first();
    sol_mp_buf last();
    sol_mp_buf next();
    sol_mp_buf prev();

    pairs_t pairs(sol::variadic_args args);
    rpairs_t rpairs(sol::variadic_args args);

    void call(sol::variadic_args args);

    void join(sol::variadic_args args);
    void leave(sol::variadic_args args);

    static bool reg(sol::state_view& lua, const std::shared_ptr<script>& s);
};

}
#endif
