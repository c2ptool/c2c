#include <websocketpp/config/asio_client.hpp>
#include <websocketpp/client.hpp>

#include <iostream>

typedef websocketpp::client<websocketpp::config::asio_tls_client> client;
typedef websocketpp::lib::shared_ptr<websocketpp::lib::asio::ssl::context> context_ptr;

using websocketpp::lib::placeholders::_1;
using websocketpp::lib::placeholders::_2;
using websocketpp::lib::bind;

void on_message(websocketpp::connection_hdl, client::message_ptr msg) {
    std::cout << msg->get_payload() << std::endl;
}

context_ptr on_tls_init(websocketpp::connection_hdl) {
    context_ptr ctx = websocketpp::lib::make_shared<boost::asio::ssl::context>(boost::asio::ssl::context::sslv23);

    try {
        ctx->set_options(boost::asio::ssl::context::default_workarounds |
                         boost::asio::ssl::context::no_sslv2 |
                         boost::asio::ssl::context::no_sslv3 |
                         boost::asio::ssl::context::single_dh_use);

        ctx->set_verify_mode(boost::asio::ssl::verify_peer|boost::asio::ssl::verify_fail_if_no_peer_cert);
        ctx->use_certificate_chain_file("client.crt");
        ctx->use_private_key_file("client.key", boost::asio::ssl::context::pem);
        //ctx->use_tmp_dh_file("dh.pem");
        ctx->load_verify_file("server.crt");
    } catch (std::exception& e) {
        std::cout << e.what() << std::endl;
    }
    return ctx;
}

int main(int argc, char* argv[]) {
    client c;

    std::string hostname = "localhost";
    std::string port = "9002";


    if (argc == 3) {
        hostname = argv[1];
        port = argv[2];
    } else {
        std::cout << "Usage: client <hostname> <port>" << std::endl;
        std::cout << "default hostname: " << hostname << std::endl;
        std::cout << "default port: " << port << std::endl;
    }
    
    std::string uri = "wss://" + hostname + ":" + port;

    try {
        c.set_access_channels(websocketpp::log::alevel::all);
        c.clear_access_channels(websocketpp::log::alevel::frame_payload);
        c.set_error_channels(websocketpp::log::elevel::all);
        c.init_asio();
        c.set_message_handler(&on_message);
        c.set_tls_init_handler(bind(&on_tls_init, ::_1));
        websocketpp::lib::error_code ec;
        client::connection_ptr con = c.get_connection(uri, ec);
        if (ec) {
            std::cout << "could not create connection because: " << ec.message() << std::endl;
            return 0;
        }
        c.connect(con);
        c.get_alog().write(websocketpp::log::alevel::app, "Connecting to " + uri);
        c.run();
    } catch (websocketpp::exception const & e) {
        std::cout << e.what() << std::endl;
    }
}
