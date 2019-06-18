#include "srv.h"
#include <boost/asio/signal_set.hpp>
#include <iostream>

int main(int argc, char *argv[])
{
    try
    {
        c2c::srv srv;
        boost::asio::io_service& ios = srv.get_io_service();
        boost::asio::signal_set exit( ios, SIGINT, SIGTERM );
        exit.async_wait([&srv, &ios](boost::system::error_code const& e, int s) {
            ios.stop();
        });
        srv.start(argc, argv);
        ios.run();
        srv.stop();
    }
    catch (const std::exception& e)
    {
        std::cout << e.what() << std::endl;
    }
    return 0;
}
