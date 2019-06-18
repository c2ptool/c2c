#include "ldb.h"
#include "script.h"
#include "work.h"
#include "msg.h"

#include <iostream>
#include <sstream>

#include "lua_cmsgpack.h"

namespace sol {

    template <>
    struct lua_size<c2c::ldb::pairs_t> : std::integral_constant<int, 2> {};
    template <>
    struct lua_size<c2c::ldb::rpairs_t> : std::integral_constant<int, 2> {};

    namespace stack
    {
        // arguments pusher
        int push(lua_State *L, c2c::mpack_param *p)
        {
            if(p->p && p->sz>0)
                return mp_unpack(L, p->p, p->sz);
            lua_pushnil(L);
            return 1;
        }

        int push(lua_State *L, c2c::var_param *p)
        {
            c2c::var2lua(p->v, L);
            return 1;
        }

        int push(lua_State *L, c2c::vec_param *p)
        {
            if(p->v)
                return c2c::vec2lua(p->v, L);
            return 0;
        }

        template <>
        struct pusher<c2c::ldb::pairs_t> {
            static int push(lua_State* L, const c2c::ldb::pairs_t& o) {
                lua_pushcfunction(L, c2c::ldb::pairs_t::iterator);
                return 1+stack::push(L, o.self);
            }
        };
        template <>
        struct pusher<c2c::ldb::rpairs_t> {
            static int push(lua_State* L, const c2c::ldb::rpairs_t& o) {
                lua_pushcfunction(L, c2c::ldb::rpairs_t::iterator);
                return 1+stack::push(L, o.self);
            }
        };
    }
}

namespace c2c {

bool ldb::reg(sol::state_view& lua, const std::shared_ptr<script>& s)
{
    auto db_new = [s](const std::string& name) -> std::shared_ptr<ldb> {
        return std::make_shared<ldb>(s, name);
    };

    lua.new_usertype<ldb>("database",
        sol::call_constructor, db_new, "new", db_new,
        sol::meta_function::index, &ldb::getter,
        sol::meta_function::new_index, &ldb::setter,
        sol::meta_function::call, &ldb::call,
        "at", &ldb::at,
        "get", &ldb::get,
        "put", &ldb::put,
        "del", &ldb::del,
        "begin", &ldb::begin,
        "commit", &ldb::commit,
        "seek", &ldb::seek,
        "skip", &ldb::skip,
        "first", &ldb::first,
        "last", &ldb::last,
        "next", &ldb::next,
        "prev", &ldb::prev,
        "pairs", &ldb::pairs,
        "rpairs", &ldb::rpairs,
        "join", &ldb::join,
        "leave", &ldb::leave
    );

    return true;
}

ldb::ldb(const std::shared_ptr<script>& s, const std::string& name)
    : s_(s)
    , name_(name)
    , postfix_len_(0)
{
    db_.open((s_.lock()->data_dir_+"/"+name).c_str());
}

ldb::ldb(const std::shared_ptr<script>& s, const std::string& name, const char *pfx, size_t sz)
    : s_(s)
    , name_(name)
    , postfix_len_(sz)
{
    db_.open((s_.lock()->data_dir_+"/"+name).c_str(), pfx, sz);
}

ldb::ldb(const std::shared_ptr<script>& s, const std::string& name, const std::string& pfx)
    : s_(s)
    , name_(name)
    , postfix_len_(pfx.size())
{
    db_.open((s_.lock()->data_dir_+"/"+name).c_str(), pfx.data(), pfx.size());
}

ldb::ldb(ldb *self)
    : s_(self->s_)
    , name_(self->name_)
    , postfix_len_(0)
{
    db_.attach(&self->db_);
}

ldb::ldb(ldb *self, const char *pfx, size_t sz)
    : s_(self->s_)
    , name_(self->name_)
    , postfix_len_(sz)
{
    db_.attach(&self->db_, pfx, sz);
}

const std::string& ldb::get_name()
{
    return name_;
}

sol::object ldb::at(sol::variadic_args args)
{
    lua_State *L = args.lua_state();

    std::string key;
    mp_pack(L, args.stack_index(), args.top(), key);

    return sol::object(L, sol::in_place, std::make_shared<ldb>(this, key.data(), key.size()));
}

sol::object ldb::getter(sol::stack_object key, sol::this_state L)
{
    std::string buf_key;
    mp_pack(L, key.stack_index(), key.stack_index(), buf_key);
    return sol::object(L, sol::in_place, std::make_shared<ldb>(this, buf_key.data(), buf_key.size()));
}

void ldb::setter(sol::stack_object k, sol::stack_object v, sol::this_state L)
{
    std::string key;
    mp_pack(L, k.stack_index(), k.stack_index(), key);

    switch(v.get_type())
    {
    case sol::type::lua_nil: db_.del(key.data(), key.size()); break;
    case sol::type::function:
        {
            auto w = s_.lock()->w_.lock();
            std::string buf;
            size_t sz; const char *pfx = db_.get_prefix(&sz);
            buf.insert(buf.end(), pfx, pfx+sz);
            buf.insert(buf.end(), key.begin(), key.end());
            vec_t vec = pack2vec(buf);
            vec->insert(vec->begin(), {name_});
            worker::server::func_info_t& fi = w->fmap_[vec];
            fi.s_ = s_;
            fi.f_ = v.as<sol::protected_function>();
        }
        break;
    default:
        {
            std::string val;
            mp_pack(L, v.stack_index(), v.stack_index(), val);
            db_.put(key.data(), key.size(), val.data(), val.size());
        }
        break;
    }
}

sol_mp_buf ldb::get(sol::variadic_args args)
{
    lua_State *L = args.lua_state();

    struct CB
    {
        sol::protected_function f_;
        bool on(connection_ptr con, const std::string& meth, var_t pars)
        {
            if(meth == "result")
            {
                sol::protected_function_result res;
                if(type(pars) ==  VEC)
                {
                    vec_param vec{mpark::get<vec_t>(pars)};
                    res = f_(con, vec);
                }
                else
                    res = f_(con, pars);
                if (!res.valid())
                {
                    sol::error err = res;
                    LOG(ERROR) << "call failed, sol::error::what() is " << err.what() << std::endl;
                }
            }
            else
            {
                std::string log = "error";
                map_t m = mpark::get<map_t>(pars);
                auto it_code = m->find(" code");
                if(it_code != m->end())
                    log += "code: " + std::to_string(mpark::get<int>(it_code->second.value));
                auto it_message = m->find("message");
                if(it_message != m->end())
                    log += " message: " + mpark::get<std::string>(it_message->second.value);
                LOG(ERROR) << log;
            }
            return true;
        }
    };

    call_t r;
    std::shared_ptr<CB> cb;

    int limit = args.top();
    if(lua_type(L, limit) == LUA_TFUNCTION)
    {
        cb = std::make_shared<CB>();
        cb->f_ = sol::stack_object(L, limit).as<sol::protected_function>();
        r = std::bind(&CB::on, cb, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3);
        limit--;
    }

    std::string key;
    mp_pack(L, args.stack_index(), limit, key);

    sol_mp_buf val;
    db_.get(key.data(), key.size(), val.data);

    if(cb)
    {
        if(peers_.size() > 0)
            s_.lock()->w_.lock()->get(name_, pack2vec(key), r, peers_);

        sol::protected_function_result res = cb->f_(val);
        if (!res.valid())
        {
            sol::error err = res;
            LOG(ERROR) << "call failed, sol::error::what() is " << err.what() << std::endl;
        }
    }

    return val;
}

void ldb::put(sol::variadic_args args)
{
    lua_State *L = args.lua_state();

    std::string key, val;
    mp_pack(L, args.stack_index(), args.top()-1, key);
    mp_pack(L, args.top(), args.top(), val);

    db_.put(key.data(), key.size(), val.data(), val.size());

    if(peers_.size() > 0)
        s_.lock()->w_.lock()->put(name_, pack2vec(key), pack2vec(val), peers_);
}

void ldb::del(sol::variadic_args args)
{
    lua_State *L = args.lua_state();

    std::string key;
    mp_pack(L, args.stack_index(), args.top(), key);

    db_.del(key.data(), key.size());

    if(peers_.size() > 0)
        s_.lock()->w_.lock()->del(name_, pack2vec(key), peers_);
}

void ldb::begin() { db_.begin(); }
void ldb::commit() { db_.commit(); }

sol_mp_buf ldb::seek(sol::variadic_args args)
{
    lua_State *L = args.lua_state();

    std::string key;
    mp_pack(L, args.stack_index(), args.top(), key);

    sol_mp_buf res;
    db_.seek(key.data(), key.size(), res.data, res.data);

    return res;
}

sol_mp_buf ldb::skip(int n)
{
    sol_mp_buf res;
    db_.skip(n, res.data, res.data);
    return res;
}

sol_mp_buf ldb::first()
{
    sol_mp_buf res;
    db_.first(res.data, res.data);
    return res;
}

sol_mp_buf ldb::last()
{
    sol_mp_buf res;
    db_.last(res.data, res.data);
    return res;
}

sol_mp_buf ldb::next()
{
    sol_mp_buf res;
    db_.next(res.data, res.data);
    return res;
}

sol_mp_buf ldb::prev()
{
    sol_mp_buf res;
    db_.prev(res.data, res.data);
    return res;
}

int ldb::pairs_t::iterator(lua_State* L)
{
    sol::stack_object selfobj(L, 1);
    ldb& self = selfobj.as<ldb>();
    return sol::stack::push(L, self.next());
}

int ldb::rpairs_t::iterator(lua_State* L)
{
    sol::stack_object selfobj(L, 1);
    ldb& self = selfobj.as<ldb>();
    return sol::stack::push(L, self.prev());
}

ldb::pairs_t ldb::pairs(sol::variadic_args args)
{
    lua_State *L = args.lua_state();
    std::string key;
    mp_pack(L, args.stack_index(), args.top(), key);
    return pairs_t(this, key.data(), key.size());
}

ldb::rpairs_t ldb::rpairs(sol::variadic_args args)
{
    lua_State *L = args.lua_state();
    std::string key;
    mp_pack(L, args.stack_index(), args.top(), key);
    return rpairs_t(this, key.data(), key.size());
}

void ldb::call(sol::variadic_args args)
{
    lua_State *L = args.lua_state();

    int limit = args.top();
    call_t r;
    if(lua_type(L, limit) == LUA_TFUNCTION)
    {
        struct CB
        {
            sol::protected_function f_;
            bool on(connection_ptr con, const std::string& meth, var_t pars)
            {
                if(meth == "result")
                {
                    sol::protected_function_result res;
                    if(type(pars) ==  VEC)
                    {
                        vec_param vec{mpark::get<vec_t>(pars)};
                        res = f_(con, vec);
                    }
                    else
                        res = f_(con, pars);
                    if (!res.valid())
                    {
                        sol::error err = res;
                        LOG(ERROR) << "call failed, sol::error::what() is " << err.what() << std::endl;
                    }
                }
                else
                {
                    std::string log = "error";
                    map_t m = mpark::get<map_t>(pars);
                    auto it_code = m->find(" code");
                    if(it_code != m->end())
                        log += "code: " + std::to_string(mpark::get<int>(it_code->second.value));
                    auto it_message = m->find("message");
                    if(it_message != m->end())
                        log += " message: " + mpark::get<std::string>(it_message->second.value);
                    LOG(ERROR) << log;
                }
                return true;
            }
        };
        std::shared_ptr<CB> cb(new CB());
        cb->f_ = sol::stack_object(L, limit).as<sol::protected_function>();
        r = std::bind(&CB::on, cb, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3);
        limit--;
    }

    size_t sz = 0;
    const char *p = db_.get_prefix(&sz);

    var_t key;
    if(sz > 0)
    {
        std::string pfx(p, sz);
        key = pack2vec(pfx);
    }

    var_t pars = lua2vec(L, args.stack_index() + 1, limit);

    auto w = s_.lock()->w_.lock();
    if(r)
        w->call_r(name_, key, pars, r, peers_);
    else
        w->call(name_, key, pars, peers_);
}

void ldb::join(sol::variadic_args args)
{
    for (auto a : args)
    {
        bool e = false;
        connection_ptr c = a;
        for (auto n : peers_)
            if(c == n) { e = true; break; }
        if(e) continue;
        peers_.push_back(c);
    }
}

void ldb::leave(sol::variadic_args args)
{
    for (auto a : args)
    {
        connection_ptr c = a;
        for (auto n=peers_.begin(); n<peers_.end(); n++)
            if(c == *n) { peers_.erase(n); break; }
    }
}

}
