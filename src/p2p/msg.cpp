#include "msg.h"
#include "easylogging++.h"

#include "rapidjson/reader.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"

#include "msgpack.hpp"
#include "lua.hpp"

#include <stack>
#include <math.h>

namespace c2c {

var_t pack2var(const std::string& data, std::size_t& off)
{
    struct context
    {
        context() : var(nullptr), is_key(false) {}
        context(context& c) : var(c.var), map(c.map), vec(c.vec), is_key(c.is_key) {}
        var_t *var;
        map_t map;
        vec_t vec;
        bool is_key;
    };

    struct visitor
    {
        std::stack<context>& stack;
        context *cur;

        visitor(std::stack<context>& s)
            : stack(s)
            , cur(&stack.top())
        {
        }

        bool ec() {
            LOG(ERROR) << "msgpack error";
            return false;
        }

        bool visit_nil() { if(!cur->var) return ec(); *cur->var = nil_t(nullptr); return true; }
        bool visit_boolean(bool v) { if(!cur->var) return ec(); *cur->var = v; return true; }
        bool visit_positive_integer(uint64_t v) { if(!cur->var) return ec(); *cur->var = v; return true; }
        bool visit_negative_integer(int64_t v) { if(!cur->var) return ec(); *cur->var = v; return true; }
        bool visit_float32(float v) { if(!cur->var) return ec(); *cur->var = v; return true; }
        bool visit_float64(double v) { if(!cur->var) return ec(); *cur->var = v; return true; }
        bool visit_str(const char* v, uint32_t sz) {
            if(cur->is_key)
            {
                if(!cur->map)
                    return ec();
                cur->var = &(*cur->map)[std::string(v, v+sz)].value;
            }
            else if(cur->var)
                *cur->var = std::string(v, sz);
            else
                return ec();
            return true;
        }
        bool visit_bin(const char* v, uint32_t sz) {
            if(!cur->var) return ec();
            *cur->var = binary_t((uint8_t *)v, (uint8_t *)v+sz);
            return true;
        }
        bool visit_ext(const char* v, uint32_t sz) {
            if(!cur->var) return ec();
            *cur->var = binary_t((uint8_t *)v, (uint8_t *)v+sz);
            return true;
        }
        bool start_array(uint32_t /*num_elements*/) {
            if(!cur->var) return ec();
            vec_t v = std::make_shared<std::vector<item_t>>();
            *cur->var = v;
            stack.emplace();
            cur = &stack.top();
            cur->vec = v;
            return true;
        }
        bool start_array_item() {
            if(!cur->vec) return ec();
            cur->vec->resize(cur->vec->size()+1);
            cur->var = &cur->vec->back().value;
            return true;
        }
        bool end_array_item() { cur->var = nullptr; return true; }
        bool end_array() {
            stack.pop();
            cur = &stack.top();
            return true;
        }
        bool start_map(uint32_t /*num_kv_pairs*/) {
            if(!cur->var) return ec();
            map_t m = std::make_shared<std::map<std::string, item_t>>();
            *cur->var = m;
            stack.emplace();
            cur = &stack.top();
            cur->map = m;
            return true;
        }
        bool start_map_key() { cur->is_key = true; return true; }
        bool end_map_key() { cur->is_key = false; return true; }
        bool start_map_value() { return true; }
        bool end_map_value() { cur->var = nullptr; return true; }
        bool end_map() {
            stack.pop();
            cur = &stack.top();
            return true;
        }
        void parse_error(size_t parsed_offset, size_t error_offset) {
            LOG(ERROR) << "msgpack parse error, parsed offset: " << parsed_offset << ", error offset: " << error_offset;
        }
        void insufficient_bytes(size_t parsed_offset, size_t error_offset) {
            LOG(ERROR) << "msgpack insufficient bytes, parsed offset: " << parsed_offset << ", error offset: " << error_offset;
        }
        bool referenced() const { return false; }
        void set_referenced(bool /*referenced*/) {}
    };

    var_t res;
    std::stack<context> stack;
    stack.emplace();
    stack.top().var = &res;
    visitor visit(stack);
    msgpack::parse(data.data(), data.size(), off, visit);
    return res;
}

var_t pack2var(const std::string& data)
{
    std::size_t off = 0;
    return pack2var(data, off);
}

vec_t pack2vec(const std::string& data)
{
    vec_t vec = std::make_shared<std::vector<item_t>>();
    std::size_t off = 0;
    while(off < data.size())
    {
        vec->resize(vec->size()+1);
        item_t& item = vec->back();
        item.value = pack2var(data, off);
    }
    return vec;
}

struct writer_t {
    std::string& data_;
    writer_t(std::string& data) : data_(data) {}
    void write(const char* buf, size_t len) { data_.insert(data_.end(), buf, buf+len); }
};

void var2pack(const var_t& var, msgpack::packer<writer_t>& pk)
{
    struct visitor
    {
        msgpack::packer<writer_t>& wr;
        visitor(msgpack::packer<writer_t>& w) : wr(w) {}
        bool operator()(nil_t) const { wr.pack_nil(); return true; }
        bool operator()(bool v) const { if(v) wr.pack_true(); else wr.pack_false(); return true; }
        bool operator()(int8_t v) const { wr.pack(v); return true; }
        bool operator()(uint8_t v) const { wr.pack(v); return true; }
        bool operator()(int16_t v) const { wr.pack(v); return true; }
        bool operator()(uint16_t v) const { wr.pack(v); return true; }
        bool operator()(int32_t v) const { wr.pack(v); return true; }
        bool operator()(uint32_t v) const { wr.pack(v); return true; }
        bool operator()(int64_t v) const { wr.pack(v); return true; }
        bool operator()(uint64_t v) const { wr.pack(v); return true; }
        bool operator()(float v) const { wr.pack(v); return true;  }
        bool operator()(double v) const { wr.pack(v); return true; }
        bool operator()(const std::string& v) const {  wr.pack_str(v.length()); wr.pack_str_body(v.c_str(), v.length()); return true; }
        bool operator()(const binary_t& v) const { wr.pack_bin(v.size()); wr.pack_bin_body((const char *)v.data(), v.size()); return true; }
        bool operator()(const map_t& v) const {
            wr.pack_map(v->size());
            for(auto n=v->cbegin(); n!=v->cend(); n++)
            {
                wr.pack_str(n->first.length());
                wr.pack_str_body(n->first.c_str(), n->first.length());
                visitor v(wr);
                mpark::visit(v, n->second.value);
            }
            return true;
        }
        bool operator()(const vec_t& v) const {
            wr.pack_array(v->size());
            for(auto n=v->cbegin(); n<v->cend(); n++)
            {
                visitor v(wr);
                mpark::visit(v, n->value);
            }
            return true;
        }
    };

    visitor v(pk);
    mpark::visit(v, var);
}

void vec2pack(const vec_t& vec, std::string& data)
{
    writer_t wr(data);
    msgpack::packer<writer_t> pk(wr);
    for(auto n=vec->cbegin(); n<vec->cend(); n++)
        var2pack(n->value, pk);
}

void var2pack(const var_t& var, std::string& data)
{
    writer_t wr(data);
    msgpack::packer<writer_t> pk(wr);
    var2pack(var, pk);
}

var_t json2var(const std::string& data)
{
    struct context
    {
        context() : var(nullptr), is_key(false), vec_is_uint8_only(false) {}
        context(context& c) : var(c.var), map(c.map), vec(c.vec), is_key(c.is_key) {}
        var_t *var;
        map_t map;
        vec_t vec;
        bool vec_is_uint8_only;
        bool is_key;
    };

    struct visitor
    {
        std::stack<context>& stack;
        context *cur;

        visitor(std::stack<context>& s)
            : stack(s)
            , cur(&stack.top())
        {
        }

        bool ec() {
            LOG(ERROR) << "json parse error";
            return false;
        }

        bool Null() { if(cur->vec) { cur->vec->resize(cur->vec->size()+1); cur->var = &cur->vec->back().value; cur->vec_is_uint8_only = false; } if(!cur->var) return ec(); *cur->var = nil_t(nullptr); return true; }
        bool Bool(bool v) { if(cur->vec) { cur->vec->resize(cur->vec->size()+1); cur->var = &cur->vec->back().value; cur->vec_is_uint8_only = false; } if(!cur->var) return ec(); *cur->var = v; return true; }
        bool Int(int v) { if(cur->vec) { cur->vec->resize(cur->vec->size()+1); cur->var = &cur->vec->back().value; if(v<0 || v>255) cur->vec_is_uint8_only = false; } if(!cur->var) return ec(); *cur->var = v; return true; }
        bool Uint(unsigned v) { if(cur->vec) { cur->vec->resize(cur->vec->size()+1); cur->var = &cur->vec->back().value; if(v>255) cur->vec_is_uint8_only = false; } if(!cur->var) return ec(); *cur->var = v; return true; }
        bool Int64(int64_t v) { if(cur->vec) { cur->vec->resize(cur->vec->size()+1); cur->var = &cur->vec->back().value; if(v<0 || v>255) cur->vec_is_uint8_only = false; } if(!cur->var) return ec(); *cur->var = v; return true; }
        bool Uint64(uint64_t v) { if(cur->vec) { cur->vec->resize(cur->vec->size()+1); cur->var = &cur->vec->back().value; if(v>255) cur->vec_is_uint8_only = false; } if(!cur->var) return ec(); *cur->var = v; return true; }
        bool Double(double v) { if(cur->vec) { cur->vec->resize(cur->vec->size()+1); cur->var = &cur->vec->back().value; cur->vec_is_uint8_only = false; } if(!cur->var) return ec(); *cur->var = v; return true; }
        bool RawNumber(const char* str, rapidjson::SizeType length, bool /*copy*/)
            { if(cur->vec) { cur->vec->resize(cur->vec->size()+1); cur->var = &cur->vec->back().value; cur->vec_is_uint8_only = false; } if(!cur->var) return ec(); *cur->var = atof(str); return true; }
        bool String(const char* str, rapidjson::SizeType length, bool /*copy*/)
            { if(cur->vec) { cur->vec->resize(cur->vec->size()+1); cur->var = &cur->vec->back().value; cur->vec_is_uint8_only = false; } if(!cur->var) return ec(); *cur->var = std::string(str, length); return true; }
        bool StartObject() {
            if(cur->vec) { cur->vec->resize(cur->vec->size()+1); cur->var = &cur->vec->back().value; cur->vec_is_uint8_only = false; }
            if(!cur->var) return ec();
            map_t m = std::make_shared<std::map<std::string, item_t>>();
            *cur->var = m;
            stack.emplace();
            cur = &stack.top();
            cur->map = m;
            return true;
        }
        bool Key(const char* str, rapidjson::SizeType length, bool /*copy*/) {
            if(!cur->map) return ec();
            cur->var = &(*cur->map)[std::string(str, length)].value;
            return true;
        }
        bool EndObject(rapidjson::SizeType /*memberCount*/) {
            stack.pop();
            cur = &stack.top();
            return true;
        }
        bool StartArray() {
            if(cur->vec) { cur->vec->resize(cur->vec->size()+1); cur->var = &cur->vec->back().value; cur->vec_is_uint8_only = false; }
            if(!cur->var) return ec();
            vec_t v = std::make_shared<std::vector<item_t>>();
            *cur->var = v;
            stack.emplace();
            cur = &stack.top();
            cur->vec = v;
            cur->vec_is_uint8_only = true;
            return true;
        }
        bool EndArray(rapidjson::SizeType /*elementCount*/) {
            bool to_bin = cur->vec_is_uint8_only;
            stack.pop();
            cur = &stack.top();
            if(to_bin)
            {
                vec_t v = mpark::get<vec_t>(*cur->var);
                struct visitor
                {
                    binary_t val;
                    bool operator()(nil_t) { return false; }
                    bool operator()(bool) { return false; }
                    bool operator()(int8_t v) { if(v<0) return false; val.push_back(v); return true; }
                    bool operator()(uint8_t v) { val.push_back(v); return true; }
                    bool operator()(int16_t v) { if(v<0 || v>255) return false; val.push_back(v); return true; }
                    bool operator()(uint16_t v) { if(v>255) return false; val.push_back(v); return true; }
                    bool operator()(int32_t v) { if(v<0 || v>255) return false; val.push_back(v); return true; }
                    bool operator()(uint32_t v) { if(v>255) return false; val.push_back(v); return true; }
                    bool operator()(int64_t v) { if(v<0 || v>255) return false; val.push_back(v); return true; }
                    bool operator()(uint64_t v) { if(v>255) return false; val.push_back(v); return true; }
                    bool operator()(float) { return false; }
                    bool operator()(double) { return false; }
                    bool operator()(const std::string&) { return false; }
                    bool operator()(const binary_t&) { return false; }
                    bool operator()(const map_t&) { return false; }
                    bool operator()(const vec_t&) { return false; }
                };
                visitor vis;
                for(auto n=v->cbegin(); n<v->cend(); n++)
                    if(!mpark::visit(vis, n->value) ) { to_bin = false; break; }
                if(to_bin)
                    *cur->var = vis.val;
            }
            return true;
        }
    };

    var_t res;
    std::stack<context> stack;
    stack.emplace();
    stack.top().var = &res;
    visitor visit(stack);
    rapidjson::Reader reader;
    rapidjson::StringStream ss(data.c_str());
    reader.Parse(ss, visit);

    return res;
}

void var2json(const var_t& var, std::string& data)
{
    struct visitor
    {
        rapidjson::Writer<rapidjson::StringBuffer>& wr;
        visitor(rapidjson::Writer<rapidjson::StringBuffer>& w) : wr(w) {}
        bool operator()(nil_t) const { return wr.Null(); }
        bool operator()(bool v) const { return wr.Bool(v); }
        bool operator()(int8_t v) const { return wr.Int(v); }
        bool operator()(uint8_t v) const { return wr.Uint(v); }
        bool operator()(int16_t v) const { return wr.Int(v); }
        bool operator()(uint16_t v) const { return wr.Uint(v); }
        bool operator()(int32_t v) const { return wr.Int(v); }
        bool operator()(uint32_t v) const { return wr.Uint(v); }
        bool operator()(int64_t v) const { return wr.Int64(v); }
        bool operator()(uint64_t v) const { return wr.Uint64(v); }
        bool operator()(float v) const { return wr.Double(double(v)); }
        bool operator()(double v) const { return wr.Double(v); }
        bool operator()(const std::string& v) const { return wr.String(v.c_str(), v.length()); }
        bool operator()(const binary_t& v) const {
            wr.StartArray();
            for(binary_t::const_iterator it=v.cbegin(); it<v.cend(); it++)
                wr.Uint(*it);
            wr.EndArray();
            return true;
        }
        bool operator()(const map_t& v) const {
            wr.StartObject();
            for(auto it=v->cbegin(); it!=v->cend(); it++)
            {
                wr.Key(it->first.c_str());
                visitor v(wr);
                mpark::visit(v, it->second.value);
            }
            wr.EndObject();
            return true;
        }
        bool operator()(const vec_t& v) const {
            wr.StartArray();
            for(auto it=v->cbegin(); it!=v->cend(); it++)
            {
                visitor v(wr);
                mpark::visit(v, it->value);
            }
            wr.EndArray();
            return true;
        }
    };

    rapidjson::StringBuffer s;
    rapidjson::Writer<rapidjson::StringBuffer> wr(s);
    visitor v(wr);
    mpark::visit(v, var);
    data = s.GetString();
}

std::string var2json(const var_t& var)
{
    std::string out;
    var2json(var, out);
    return out;
}

void var2lua(const var_t& var, lua_State *L)
{
    struct visitor
    {
        lua_State *L;
        visitor(lua_State *l) : L(l) {}
        bool operator()(nil_t) const { lua_pushnil(L); return true; }
        bool operator()(bool v) const { lua_pushboolean(L, int(v)); return true; }
        bool operator()(int8_t v) const { lua_pushinteger(L, int(v)); return true; }
        bool operator()(uint8_t v) const { lua_pushinteger(L, int(v)); return true; }
        bool operator()(int16_t v) const { lua_pushinteger(L, int(v)); return true; }
        bool operator()(uint16_t v) const { lua_pushinteger(L, int(v)); return true; }
        bool operator()(int32_t v) const { lua_pushinteger(L, int(v)); return true; }
        bool operator()(uint32_t v) const { lua_pushnumber(L, lua_Number(v)); return true; }
        bool operator()(int64_t v) const { lua_pushnumber(L, lua_Number(v)); return true; }
        bool operator()(uint64_t v) const { lua_pushnumber(L, lua_Number(v)); return true; }
        bool operator()(float v) const { lua_pushboolean(L, int(v)); return true; }
        bool operator()(double v) const { lua_pushboolean(L, int(v)); return true; }
        bool operator()(const std::string& v) const { lua_pushlstring(L, v.data(), v.size()); return true; }
        bool operator()(const binary_t& v) const { lua_pushlstring(L, (const char *)v.data(), v.size()); return true; }
        bool operator()(const map_t& v) const {
            lua_newtable(L);
            for(auto it=v->cbegin(); it!=v->cend(); it++)
            {
                lua_pushstring(L, it->first.c_str());
                visitor v(L);
                mpark::visit(v, it->second.value);
                lua_settable(L,-3);
            }
            return true;
        }
        bool operator()(const vec_t& v) const {
            lua_newtable(L); int index = 1;
            for(auto it=v->cbegin(); it!=v->cend(); it++)
            {
                lua_pushinteger(L, index);
                visitor v(L);
                mpark::visit(v, it->value);
                lua_settable(L,-3);
            }
            return true;
        }
    };
    visitor vis(L);
    mpark::visit(vis, var);
}

int vec2lua(const vec_t& vec, lua_State *L)
{
    for(const item_t& v : *vec)
        var2lua(v.value, L);
    return int(vec->size());
}

var_t lua2var(lua_State *L, int n)
{
    var_t out;

    switch(lua_type(L, n))
    {
    case LUA_TBOOLEAN:
        out = lua_toboolean(L, n)? true : false;
        break;
    case LUA_TNUMBER:
        {
            double v = lua_tonumber(L, n);
            if(v == floor(v))
                out = int64_t(v);
            else
                out = v;
        }
        break;
    case LUA_TSTRING:
        {
            size_t sz = 0;
            const char *p = lua_tolstring(L, n, &sz);
            out = std::string(p, sz);
        }
        break;
    case LUA_TTABLE:
        {
            lua_pushvalue(L, n);
            lua_pushnil( L );

            bool is_array = true;
            for(int n = 1; lua_next(L, -2) != 0; n++ )
            {
                if(is_array && (lua_type(L, -2) != LUA_TNUMBER || n != lua_tointeger(L, -2)))
                {
                    is_array = false;
                    break;
                }
                lua_pop(L, 1);
            }

            lua_pop(L, 1);

            if(is_array)
            {
                vec_t v( new std::vector<item_t>() );

                lua_pushvalue(L, n);
                lua_pushnil( L );

                for(int n = 0; lua_next(L, -2) != 0; n++ )
                {
                    v->push_back({lua2var(L, -1)});
                    lua_pop(L, 1);
                }

                lua_pop(L, 1);

                out = v;
            }
            else
            {
                map_t v( new std::map<std::string, item_t>() );

                lua_pushvalue(L, n);
                lua_pushnil( L );

                for(int n = 0; lua_next(L, -2) != 0; n++ )
                {
                    item_t& i = (*v)[lua_tostring(L, -2)];
                    i.value = lua2var(L, -1);

                    lua_pop(L, 1);
                }

                lua_pop(L, 1);

                out = v;
            }
        }
        break;
    default:
        out = NIL;
        break;
    }
    return out;
}

vec_t lua2vec(lua_State *L, int offset, int limit)
{
    vec_t out( new std::vector<item_t>() );
    for(int n=offset; n<=limit; n++)
        out->push_back( {lua2var(L, n)} );
    return out;
}

}
