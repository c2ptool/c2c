#ifndef L_WORKER_H
#define L_WORKER_H

#include "p2p.h"
#include "script.h"

#include <boost/asio/io_service_strand.hpp>

namespace c2c {
namespace worker {

class server : public std::enable_shared_from_this<server>
{
    friend class c2c::ldb;

    std::shared_ptr<p2p::server> p2p_;

    typedef std::set<connection_ptr, std::owner_less<connection_ptr>> peers_map;
    peers_map peers_;

    std::string script_dir_;
    std::string data_dir_;

    std::vector<std::string> lua_path_;
    std::vector<std::string> lua_cpath_;
    std::string debug_conn_;

    std::vector<std::string> args_;
    std::map<std::string, std::shared_ptr<script>> scripts_;

    void __open(connection_ptr con);
    void __close(connection_ptr con);
    bool __call(connection_ptr con, const std::string& method, const var_t& params);
    bool __call_r(connection_ptr con, const std::string& method, const var_t& params, call_t reply);

    typedef std::map<std::string, func_t> func_map;
    func_map func_;

    typedef std::map<std::string, func_r_t> func_r_map;
    func_r_map func_r_;

    static std::vector<connection_ptr> empty_peers_;

    void on_put(connection_ptr con, std::string db, var_t key, var_t val);
    void on_del(connection_ptr con, std::string db, var_t key);
    void on_get(connection_ptr con, std::string db, var_t key, call_t reply);
    void on_call(connection_ptr con, std::string db, var_t key, var_t pars);
    void on_call_r(connection_ptr con, std::string db, var_t key, var_t pars, call_t reply);

protected:
    struct func_info_t {
        sol::protected_function f_;
        std::weak_ptr<script> s_;
    };
    std::map<var_t, func_info_t> fmap_;

public:
    static void set_options_desc(boost::program_options::options_description_easy_init& options);
    server(std::shared_ptr<p2p::server> p2p, boost::program_options::variables_map& vm);

    void start();

    void put(std::string db, var_t key, var_t val, const std::vector<connection_ptr>& peers);
    void del(std::string db, var_t key, const std::vector<connection_ptr>& peers);
    void get(std::string db, var_t key, call_t reply, const std::vector<connection_ptr>& peers);
    void call(std::string db, var_t key, var_t pars, const std::vector<connection_ptr>& peers);
    void call_r(std::string db, var_t key, var_t pars, call_t reply, const std::vector<connection_ptr>& peers);

    static const std::vector<connection_ptr>& empty_peers() { return empty_peers_; }
};

}
}

#endif
