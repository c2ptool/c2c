#include "ldb.h"
#include "lresponse.h"
#include "work.h"
#include "util.h"
#include "msg.h"

#include <boost/asio/deadline_timer.hpp>

using namespace std::placeholders;

namespace c2c {
namespace worker {

void server::set_options_desc(boost::program_options::options_description_easy_init& options)
{
    options ("data-dir", boost::program_options::value<std::string>(), "path of data directory")
            ("script-dir", boost::program_options::value<std::string>(), "path of scripts directory")
            ("script", boost::program_options::value<std::vector<std::string>>(), "filepath of lua scripts")
            ("args", boost::program_options::value<std::vector<std::string>>(), "args for lua scripts")
            ("module-path", boost::program_options::value<std::vector<std::string>>(), "path's of lua modules")
            ("module-cpath", boost::program_options::value<std::vector<std::string>>(), "path's of c modules")
            ("debug", boost::program_options::value<std::string>(), "debug connection");
}

server::server(std::shared_ptr<p2p::server> p2p, boost::program_options::variables_map& vm)
    : p2p_(p2p)
{
    std::string root_dir;
    if(vm.count("root-dir") > 0) root_dir = vm["root-dir"].as<std::string>().c_str();

    if(vm.count("script-dir") > 0) script_dir_ = path_normalize(root_dir, vm["script-dir"].as<std::string>().c_str());
    if(vm.count("data-dir") > 0) data_dir_ = path_normalize(root_dir, vm["data-dir"].as<std::string>().c_str());

    if(vm.count("module-path") > 0) lua_path_ = vm["module-path"].as<std::vector<std::string>>();
    for(std::string& a : lua_path_)
        a = path_normalize(script_dir_, a);

    if(vm.count("module-cpath") > 0) lua_cpath_ = vm["module-cpath"].as<std::vector<std::string>>();
    for(std::string& a : lua_cpath_)
        a = path_normalize(script_dir_, a);

    if(vm.count("debug") > 0) debug_conn_ = vm["debug"].as<std::string>().c_str();

    std::vector<std::string> scripts;
    if(vm.count("script") > 0) scripts = vm["script"].as<std::vector<std::string>>();
    for(std::string& s : scripts)
        scripts_.insert(std::pair<std::string,script*>(filepath_normalize(script_dir_, s),nullptr));

    if(vm.count("args") > 0) args_ = vm["args"].as<std::vector<std::string>>();
}

class timeout : public  std::enable_shared_from_this<timeout>
{
    boost::asio::deadline_timer tm_;
    sol::protected_function f_;
public:
    timeout(boost::asio::io_service& ios, const sol::protected_function& f)
        : tm_(ios), f_(f)
    {
    }
    void do_timeout(double t)
    {
        tm_.expires_from_now(boost::posix_time::millisec(uint64_t(t*1000)));
        tm_.async_wait(std::bind(&timeout::on_timeout, shared_from_this(), std::placeholders::_1));
    }
    void on_timeout(boost::system::error_code const& ec)
    {
        try
        {
            sol::protected_function_result res = f_();
            if (!res.valid()) {
                sol::error err = res;
                sol::call_status status = res.status();
                LOG(ERROR) << "Lua wrong " << sol::to_string(status) << " error\n\t" << err.what();
            }
        }
        catch(const std::exception& e)
        {
            LOG(ERROR) << e.what();
        }
    }
    static bool reg(sol::state_view& lua, boost::asio::io_service& ios)
    {
        lua["timeout"] = [&ios](double t, const sol::protected_function& f)
        {
            auto to = std::make_shared<timeout>(ios, f);
            to->do_timeout(t);
        };
        return true;
    }
};

void server::start()
{
    auto f_put = std::bind(&server::on_put, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4);
    auto f_del = std::bind(&server::on_del, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3);
    auto f_get = std::bind(&server::on_get, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4);
    auto f_call = std::bind(&server::on_call, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4);
    auto f_call_r = std::bind(&server::on_call_r, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5);

    func_["put"] = [f_put](connection_ptr con, var_t pars) -> bool {
        vec_t& vec = mpark::get<vec_t>(pars);
        if(vec->size() != 3)
            throw std::runtime_error("error count of parameters");
        f_put(con, mpark::get<std::string>((*vec)[0].value), (*vec)[1].value, (*vec)[2].value);
        return true;
    };

    func_["del"] = [f_del](connection_ptr con, var_t pars) -> bool {
        vec_t& vec = mpark::get<vec_t>(pars);
        if(vec->size() != 2)
            throw std::runtime_error("error count of parameters");
        f_del(con, mpark::get<std::string>((*vec)[0].value), (*vec)[1].value);
        return true;
    };

    func_r_["get"] = [f_get](connection_ptr con, var_t pars, call_t r) -> bool {
        vec_t& vec = mpark::get<vec_t>(pars);
        if(vec->size() != 2)
            throw std::runtime_error("error count of parameters");
        f_get(con, mpark::get<std::string>((*vec)[0].value), (*vec)[1].value, r);
        return true;
    };

    func_["call"] = [f_call](connection_ptr con, var_t pars) -> bool {
        vec_t& vec = mpark::get<vec_t>(pars);
        if(vec->size() != 3)
            throw std::runtime_error("error count of parameters");
        f_call(con, mpark::get<std::string>((*vec)[0].value), (*vec)[1].value, (*vec)[2].value);
        return true;
    };

    func_r_["call"] = [f_call_r](connection_ptr con, var_t pars, call_t r) -> bool {
        vec_t& vec = mpark::get<vec_t>(pars);
        if(vec->size() != 3)
            throw std::runtime_error("error count of parameters");
        f_call_r(con, mpark::get<std::string>((*vec)[0].value), (*vec)[1].value, (*vec)[2].value, r);
        return true;
    };

    for(auto it=scripts_.begin(); it!=scripts_.end(); it++)
    {
        try
        {
            std::shared_ptr<script> s(new script(shared_from_this()));
            s->init(data_dir_, lua_path_, lua_cpath_, args_, debug_conn_);
            timeout::reg(s->L_, p2p_->get_io_service());
            s->open(it->first);
            it->second = s;
        }
        catch (const std::exception& e)
        {
            LOG(ERROR) << e.what();
        }
    }

    p2p_->join("data",
        std::bind(&server::__open, this, _1),
        std::bind(&server::__close, this, _1),
        std::bind(&server::__call, this, _1, _2, _3),
        std::bind(&server::__call_r, this, _1, _2, _3, _4));
}

void server::__open(connection_ptr con)
{
    peers_.insert(con);
}

void server::__close(connection_ptr con)
{
    peers_.erase(con);
}

bool server::__call(connection_ptr con, const std::string& method, const var_t& params)
{
    try
    {
        func_map::iterator m = func_.find(method);
        if(m != func_.end())
            return m->second(con, params);
    }
    catch (const std::exception& e)
    {
        LOG(ERROR) << e.what();
    }
    return false;
}

bool server::__call_r(connection_ptr con, const std::string& method, const var_t& params, call_t reply)
{
    try
    {
        func_r_map::iterator m = func_r_.find(method);
        if(m != func_r_.end())
            return m->second(con, params, reply);
    }
    catch (const std::exception& e)
    {
        LOG(ERROR) << e.what();
    }
    return false;
}

std::vector<connection_ptr> server::empty_peers_;

void server::on_put(connection_ptr con, std::string name, var_t key, var_t val)
{
    put(name, key, val, empty_peers());
}

void server::put(std::string name, var_t key, var_t val, const std::vector<connection_ptr>& peers)
{
    std::string path = filepath_normalize(data_dir_, name);
    db_layer<DB_DATA_LAYER> db;
    if(db.open(path.c_str()))
    {
        std::string k,v;
        if(type(key) == VEC)
        {
            vec_t& vec = mpark::get<vec_t>(key);
            var2pack(vec, k);
        }
        else
            var2pack(key, k);
        var2pack(val, v);
        db.put(k.data(), k.size(), v.data(), v.size());
    }
    else
    {
        LOG(ERROR) << "can not open db: " << path;
    }
}

void server::on_del(connection_ptr con, std::string name, var_t key)
{
    del(name, key, empty_peers());
}

void server::del(std::string name, var_t key, const std::vector<connection_ptr>& peers)
{
    std::string path = filepath_normalize(data_dir_, name);
    db_layer<DB_DATA_LAYER> db;
    if(db.open(path.c_str()))
    {
        std::string k;
        if(type(key) == VEC)
        {
            vec_t& vec = mpark::get<vec_t>(key);
            var2pack(vec, k);
        }
        else
            var2pack(key, k);
        db.del(k.data(), k.size());
    }
    else
    {
        LOG(ERROR) << "can not open db: " << path;
    }
}

void server::on_get(connection_ptr con, std::string name, var_t key, call_t reply)
{
    get(name, key, reply, empty_peers());
}

void server::get(std::string name, var_t key, call_t reply, const std::vector<connection_ptr>& peers)
{
    std::string path = filepath_normalize(data_dir_, name);
    db_layer<DB_DATA_LAYER> db;
    if(db.open(path.c_str()))
    {
        std::string k;
        if(type(key) == VEC)
        {
            vec_t& vec = mpark::get<vec_t>(key);
            var2pack(vec, k);
        }
        else
            var2pack(key, k);
        std::string res;
        if(!db.get(k.data(), k.size(), res))
        {
            std::string jk;
            var2json(key, k);
            LOG(ERROR) << "key: " << jk << "is not found in db: " << path;
            reply(connection_ptr(), "error", json2var("{\"message\":\"key not found\",\"code\":-1"));
        }
        else
            reply(connection_ptr(), "result", pack2var(res));
    }
    else
    {
        LOG(ERROR) << "can not open db: " << path;
    }
}

void server::on_call(connection_ptr con, std::string db, var_t key, var_t pars)
{
    call(db, key, pars, empty_peers());
}

void server::call(std::string name, var_t key, var_t args, const std::vector<connection_ptr>& peers)
{
    vec_t fk;
    if(type(key) ==  VEC)
        fk = mpark::get<vec_t>(key);
    else
        fk->push_back({key});
    fk->insert(fk->begin(), {name});
    auto f = fmap_.find(fk);
    if(f != fmap_.end())
    {
        vec_t kp = mpark::get<vec_t>(key);
        std::string fn;
        var2pack(kp->back().value, fn);
        kp->pop_back();
        std::string pfx;
        vec2pack(kp, pfx);
        std::shared_ptr<ldb> db(new ldb(f->second.s_.lock(), name, pfx));
        sol::protected_function_result res;
        if(type(args) ==  VEC)
        {
            vec_param vec{mpark::get<vec_t>(args)};
            res = f->second.f_(db, vec);
        }
        else
            res = f->second.f_(db, args);
        if (!res.valid())
        {
            sol::error err = res;
            LOG(ERROR) << "call failed, sol::error::what() is " << err.what() << std::endl;
        }
    }

    if(peers.size() > 0)
    {
        vec_t pars = std::make_shared<std::vector<item_t>>();
        pars->push_back({name});
        pars->push_back({key});
        pars->push_back({args});
        p2p_->call("call", pars, peers);
    }
}

void server::on_call_r(connection_ptr con, std::string db, var_t key, var_t pars, call_t reply)
{
    call_r(db, key, pars, reply, empty_peers());
}

void server::call_r(std::string name, var_t key, var_t args, call_t reply, const std::vector<connection_ptr>& peers)
{
    vec_t fk;
    if(type(key) ==  VEC)
        fk = mpark::get<vec_t>(key);
    else
        fk->push_back({key});
    fk->insert(fk->begin(), {name});
    auto f = fmap_.find(fk);
    if(f != fmap_.end())
    {
        vec_t kp = mpark::get<vec_t>(key);
        std::string fn;
        var2pack(kp->back().value, fn);
        kp->pop_back();
        std::string pfx;
        vec2pack(kp, pfx);
        std::shared_ptr<ldb> db(new ldb(f->second.s_.lock(), name, pfx));
        std::shared_ptr<lua::response> response(new lua::response(shared_from_this(), reply));
        sol::protected_function_result res;
        if(type(args) ==  VEC)
        {
            vec_param vec{mpark::get<vec_t>(args)};
            res = f->second.f_(db, vec, response);
        }
        else
            res = f->second.f_(db, args, response);
        if (!res.valid())
        {
            sol::error err = res;
            LOG(ERROR) << "call failed, sol::error::what() is " << err.what() << std::endl;
        }
    }

    if(peers.size() > 0)
    {
        vec_t pars = std::make_shared<std::vector<item_t>>();
        pars->push_back({name});
        pars->push_back({key});
        pars->push_back({args});
        p2p_->call("call", pars, reply, peers);
    }
}

}
}
