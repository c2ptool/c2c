#ifndef L_SCRIPT_H
#define L_SCRIPT_H

#include "sol.h"

namespace c2c {

namespace worker {
    class server;
}

class ldb;

class script : public std::enable_shared_from_this<script>
{
    friend class worker::server;
    friend class ldb;

    std::string name_;
    std::string data_dir_;

protected:
    std::weak_ptr<worker::server> w_;
    sol::state L_;

public:
    script(const std::shared_ptr<worker::server>& w);
    bool init(const std::string& data_dir,
           const std::vector<std::string>& lua_path,
           const std::vector<std::string>& lua_cpath,
           const std::vector<std::string>& lua_args,
           const std::string& debug_conn);
    bool open(const std::string& name);
    void close();
    const std::string& name() { return name_; }
};

}

#endif
