#ifndef L_SRV_H
#define L_SRV_H

#include "var.h"
#include "func.h"

#include <memory>
#include <thread>

#include <boost/asio/io_service.hpp>

namespace c2c
{
    namespace p2p { class server; }
    namespace worker { class server; }

    class srv
    {
        std::shared_ptr<c2c::p2p::server> p2p_;
        std::shared_ptr<c2c::worker::server> work_;

        std::thread thr_;
        boost::asio::io_service ios_;

    public:
        srv();

        void start(int arvc, char *argv[]);
        void stop();

        boost::asio::io_service& get_io_service() { return ios_; }

        void put(std::string db, var_t key, var_t val);
        void del(std::string db, var_t key);
        void get(std::string db, var_t key, call_t reply);
        void call(std::string db, var_t key, var_t pars);
        void call_r(std::string db, var_t key, var_t pars, call_t reply);

        static srv& instance();
    };
}

#endif
