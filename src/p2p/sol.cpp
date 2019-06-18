#include "sol.h"

#include "rapidjson/reader.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"
#include "rapidjson/error/en.h"

sol::object json_to_lua(const std::string& s, sol::state_view L, std::string *err)
{
    struct level_t
    {
        sol::state_view L;
        int n; std::string key; sol::table o;
        std::unique_ptr<level_t> next;

        level_t(sol::state_view l, bool is_object = false) : L(l), n(is_object?0:1) { o = l.create_table(); }
        bool Null() { if(next.get()) return next->Null(); if(n>0) { o[n] = sol::nil; n++; } return true; }
        bool Bool(bool v) { if(next.get()) return next->Bool(v); if(n>0) { o[n] = v; n++; } else o[key] = v; return true; }
        bool Int(int v) { if(next.get()) return next->Int(v); if(n>0) { o[n] = v; n++; } else o[key] = v; return true; }
        bool Uint(unsigned v) { if(next.get()) return next->Uint(v); if(n>0) { o[n] = v; n++; } else o[key] = v; return true; }
        bool Int64(int64_t v) { if(next.get()) return next->Int64(v); if(n>0) { o[n] = v; n++; } else o[key] = v; return true; }
        bool Uint64(uint64_t v) { if(next.get()) return next->Uint64(v); if(n>0) { o[n] = v; n++; } else o[key] = v; return true; }
        bool Double(double v) { if(next.get()) return next->Double(v); if(n>0) { o[n] = v; n++; } else o[key] = v; return true; }
        bool RawNumber(const char* v, rapidjson::SizeType len, bool copy) { if(next.get()) return next->RawNumber(v, len, copy); double f = atof(std::string(v, v+len).c_str()); if(n>0) { o[n] = f; n++; } else o[key] = f; return true; }
        bool String(const char* v, rapidjson::SizeType len, bool copy)
        {
            if(next.get())
                return next->String(v, len, copy);
            std::string s(v, v+len);
            if(n>0)
                { o[n] = s; n++; }
            else
                o[key] = s;
            return true;
        }
        bool Key(const char* v, rapidjson::SizeType len, bool copy)
        {
            if(next.get())
                return next->Key(v, len, copy);
            key.assign(v, len);
            return true;
        }
        bool StartObject()
        {
            if(next.get())
                return next->StartObject();
            next.reset(new level_t(L, true));
            return true;
        }
        bool EndObject(rapidjson::SizeType cnt)
        {
            if(next.get()) {
                if(!next->next.get()) {
                    if(n>0)
                        { o[n] = next->o; n++; }
                    else
                        o[key] = next->o;
                    next.reset();
                }
                else
                    return next->EndObject(cnt);
            }
            return true;
        }
        bool StartArray()
        {
            if(next.get())
                return next->StartArray();
            next.reset(new level_t(L));
            return true;
        }
        bool EndArray(rapidjson::SizeType cnt)
        {
            if(next.get()) {
                if(!next->next.get()) {
                    if(n>0)
                        { o[n] = next->o; n++; }
                    else
                        o[key] = next->o;
                    next.reset();
                }
                else
                    return next->EndArray(cnt);
            }
            return true;
        }
    };

    level_t l(L);
    rapidjson::Reader reader;
    rapidjson::StringStream ss(s.c_str());
    if (!reader.Parse(ss, l) && err)
    {
        std::stringstream ss;
        ss<<"json error("<<static_cast<unsigned>(reader.GetErrorOffset())<<") "<<GetParseError_En(reader.GetParseErrorCode());
        *err = ss.str();
    }
    if(l.o.size() == 1)
        return  l.o[1];
    return l.o;
}

bool lua_to_json(const sol::object& v, rapidjson::Writer<rapidjson::StringBuffer>& out)
{
    sol::type type = v.get_type();
    switch (type) {
    case sol::type::boolean: out.Bool(v.as<bool>()?true:false); break;
    case sol::type::number:
        {
            double n = v.as<double>();
            if(n == floor(n))
                out.Int64(n);
            else
                out.Double(n);
        }
        break;
    case sol::type::string: out.String(v.as<std::string>().c_str()); break;
    case sol::type::table:
        {
            sol::table t = v.as<sol::table>();
            int n=-1; bool is_array=true;
            t.for_each([&](std::pair<sol::object, sol::object> kvp)
            {
                if(is_array) {
                    if(kvp.first.get_type()!=sol::type::number)
                        is_array=false;
                    if(is_array) {
                        double d=kvp.first.as<double>();
                        if(d==floor(d)) {
                            if(n==-1)
                                n = kvp.first.as<int>();
                            else if(n != kvp.first.as<int>())
                                is_array=false;
                        }
                        else
                            is_array=false;
                    }
                    if(n >= 0) n++;
                }
            });
            if(is_array)
            {
                out.StartArray();
                t.for_each([&](std::pair<sol::object, sol::object> kvp) {
                    lua_to_json(kvp.second, out);
                });
                out.EndArray();
            }
            else
            {
                out.StartObject();
                t.for_each([&](std::pair<sol::object, sol::object> kvp) {
                    out.Key(kvp.first.as<std::string>().c_str());
                    lua_to_json(kvp.second, out);
                });
                out.EndObject();
            }
        }
        break;
    default: out.Null(); break;
    }

    return true;
}

bool lua_to_json(const sol::object& v, std::string& out)
{
    rapidjson::StringBuffer json;
    rapidjson::Writer<rapidjson::StringBuffer> w(json);
    bool rc = lua_to_json(v, w);
    out = json.GetString();
    return rc;
}
