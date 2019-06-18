#ifndef L_P2P_H
#define L_P2P_H

#include "easylogging++.h"
#include "conn.h"
#include "func.h"

#include <boost/asio/io_service.hpp>
#include <boost/asio/io_service_strand.hpp>
#include <boost/program_options.hpp>

#include <memory>

namespace c2c {
namespace p2p {

class server
{
protected:
    boost::asio::io_service& ios_;
    boost::asio::io_service::strand strand_;
public:
    server(boost::asio::io_service& ios);
    virtual ~server();

    static std::shared_ptr<server> create(boost::asio::io_service& ios, boost::program_options::variables_map& vm);
    static void set_options_desc(boost::program_options::options_description_easy_init& options);

    boost::asio::io_service& get_io_service() { return ios_; }

    virtual connection_ptr connect(const std::vector<std::string>& proto, const std::string& uri, const std::string& ca = std::string()) = 0;

    virtual void close(connection_ptr) = 0;

    virtual void call(const std::string& method, var_t params, const std::vector<connection_ptr>& peers = std::vector<connection_ptr>()) = 0;
    virtual void call(const std::string& method, var_t params, call_t reply, const std::vector<connection_ptr>& peers = std::vector<connection_ptr>()) = 0;

    virtual bool start() = 0;

    virtual void join(const std::string&, const on_connection_t&, const on_connection_t&, const call_t&, const call_r_t&) = 0;
    virtual void leave(const std::string&) = 0;

    virtual void sign(const std::string& data, std::string& sig) = 0;

    virtual std::string self_id() = 0;
};

}
}

#endif
