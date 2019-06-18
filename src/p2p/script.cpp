#include <iostream>
#include <sstream>

#include <boost/algorithm/string.hpp>

#include "easylogging++.h"
#include "script.h"
#include "ldb.h"
#include "lresponse.h"

namespace c2c {

script::script(const std::shared_ptr<worker::server>& w)
    : w_(w)
{}

bool script::init(const std::string& data_dir,
               const std::vector<std::string>& lua_path,
               const std::vector<std::string>& lua_cpath,
               const std::vector<std::string>& lua_args,
               const std::string& debug_conn)
{
    L_.open_libraries();
    data_dir_ = data_dir;

    auto g_package = L_["package"];
    std::string path = g_package["path"];
    for(auto x : lua_path)
        path += ";"+x+"/?.lua";
    g_package["path"] = path;
    std::string cpath = g_package["cpath"];
    for(auto x : lua_cpath)
        cpath += ";"+x+"/?.so";
    g_package["cpath"] = cpath;

    if(debug_conn.length())
    {
        std::string s;
        std::vector<std::string> s1;
        boost::split(s1,debug_conn,boost::is_any_of("@"));
        if(s1.size()==2)
        {
            std::vector<std::string> s2;
            boost::split(s2,s1[1],boost::is_any_of(":"));
            if(s1.size()==2)
            {
                s = "io.stdout:setvbuf('no') require('debugger')(";
                s += "'"+s2[0]+"',"+s2[1]+",'"+s1[0]+"') require 'debugger.plugins.ffi'";
            }
            else if(s1.size()==1)
            {
                s = "io.stdout:setvbuf('no') require('debugger')(";
                s += "'"+s2[0]+"',10000,'"+s1[0]+"') require 'debugger.plugins.ffi'";
            }
        }
        else if(s1.size()==1)
        {
            std::vector<std::string> s2;
            boost::split(s2,s1[0],boost::is_any_of(":"));
            if(s1.size()==2)
            {
                s ="io.stdout:setvbuf('no') require('debugger')(";
                s += "'"+s2[0]+"',"+s2[1]+") require 'debugger.plugins.ffi'";
            }
            else if(s1.size()==1)
            {
                s = "io.stdout:setvbuf('no') require('debugger')(";
                s += "'"+s2[0]+"',10000) require 'debugger.plugins.ffi'";
            }
        }
        L_.do_string(s);
    }
    lua::response::reg(L_);
    L_.new_usertype<connection_t>("connection_t",
        "address", sol::property([](connection_t& c)
        { return std::string((const char *)c.id.data(), c.id.size()); }));
    ldb::reg(L_, shared_from_this());
    if(lua_args.size()>0) {
        for(auto x : lua_args)
        {
            sol::protected_function_result res = L_.do_string(x.c_str());
            if (!res.valid()) {
                sol::error err = res;
                sol::call_status status = res.status();
                LOG(ERROR) << "Lua wrong " << sol::to_string(status) << " error\n\t" << err.what();
            }
        }
    }
    return true;
}

bool script::open(const std::string& name)
{
    name_ = name;
    sol::protected_function_result res =
        L_.script_file(name_);

    if (!res.valid()) {
        sol::error err = res;
        sol::call_status status = res.status();
        LOG(ERROR) << "Lua wrong " << sol::to_string(status)
                  << " error\n\t" << err.what() << std::endl;
        return false;
    }
    return true;
}

void script::close()
{
    sol::object f = L_["on_close"];
    if(f.get_type()==sol::type::function)
        f.as<sol::function>()();
}

}
