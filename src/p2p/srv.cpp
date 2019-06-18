#include "srv.h"

#include "easylogging++.h"

#include <boost/program_options.hpp>

#include <iostream>
#include <fstream>

#include "p2p.h"
#include "work.h"

INITIALIZE_EASYLOGGINGPP

using namespace std::placeholders;
namespace po = boost::program_options;

namespace c2c {

srv::srv()
{
}

void srv::start(int argc, char *argv[])
{
    el::Loggers::addFlag(el::LoggingFlag::ColoredTerminalOutput);

    po::options_description desc("Options");
    boost::program_options::options_description_easy_init opt = desc.add_options();

    c2c::p2p::server::set_options_desc(opt);
    c2c::worker::server::set_options_desc(opt);

    opt("config-file", po::value<std::string>(), "filepath of config");

    po::variables_map vm;

    try
    {
        po::store(po::parse_command_line(argc, argv, desc), vm);

        if(vm.count("config-file") > 0)
        {
            std::string fpath = vm["config-file"].as<std::string>();
            std::ifstream fconfig(fpath);
            po::store(po::parse_config_file<char>(fconfig , desc), vm);
        }

        p2p_ = c2c::p2p::server::create(ios_, vm);
        p2p_->start();

        work_ = std::make_shared<c2c::worker::server>(p2p_, vm);
        work_->start();
    }
    catch(const std::exception& e)
    {
        LOG(ERROR) << e.what();
        return;
    }

    thr_ = std::thread([this]{ ios_.run(); });
}

void srv::stop()
{
    ios_.stop();
    thr_.join();

    LOG(INFO) << "p2p service stopped";
}

void srv::put(std::string db, var_t key, var_t val)
{
    work_->put(db, key, val, worker::server::empty_peers());
}

void srv::del(std::string db, var_t key)
{
    work_->del(db, key, worker::server::empty_peers());
}

void srv::get(std::string db, var_t key, call_t reply)
{
    work_->get(db, key, reply, worker::server::empty_peers());
}

void srv::call(std::string db, var_t key, var_t pars)
{
    work_->call(db, key, pars, worker::server::empty_peers());
}

void srv::call_r(std::string db, var_t key, var_t pars, call_t reply)
{
    work_->call_r(db, key, pars, reply, worker::server::empty_peers());
}

srv& srv::instance()
{
    static srv it;
    return it;
}

}
