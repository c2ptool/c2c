#include <websocketpp/config/asio.hpp>
#include <websocketpp/server.hpp>
#include <iostream>

#include "mkcert.h"

//#include <stdio.h>
//#include <openssl/rsa.h>
//#include <openssl/pem.h>

inline std::string to_hex(std::string const & input) {
    std::string output;
    std::string hex = "0123456789ABCDEF";

    for (size_t i = 0; i < input.size(); i++) {
        output += hex[(input[i] & 0xF0) >> 4];
        output += hex[input[i] & 0x0F];
        output += " ";
    }

    return output;
}

typedef websocketpp::server<websocketpp::config::asio_tls> server;

using websocketpp::lib::placeholders::_1;
using websocketpp::lib::placeholders::_2;
using websocketpp::lib::bind;

// pull out the type of messages sent by our config
typedef websocketpp::config::asio::message_type::ptr message_ptr;
typedef websocketpp::lib::shared_ptr<websocketpp::lib::asio::ssl::context> context_ptr;

void on_message(server* s, websocketpp::connection_hdl hdl, message_ptr msg) {
    std::cout << "on_message called with hdl: " << hdl.lock().get()
              << " and message: " << msg->get_payload()
              << std::endl;

    try {
        s->send(hdl, msg->get_payload(), msg->get_opcode());
    } catch (websocketpp::exception const & e) {
        std::cout << "Echo failed because: "
                  << "(" << e.what() << ")" << std::endl;
    }
}

void on_http(server* s, websocketpp::connection_hdl hdl) {
    server::connection_ptr con = s->get_con_from_hdl(hdl);
    
    con->set_body("Hello World!");
    con->set_status(websocketpp::http::status_code::ok);
}

std::string get_password() {
    return "test";
}

bool on_verify_certificate(websocketpp::connection_hdl hdl, bool preverified, boost::asio::ssl::verify_context& ctx)
{
    int depth = X509_STORE_CTX_get_error_depth(ctx.native_handle());
    if (depth > 0)
        return true;
    X509* cert = X509_STORE_CTX_get_current_cert(ctx.native_handle());
    unsigned char md[EVP_MAX_MD_SIZE];
    const EVP_MD *digest = EVP_get_digestbyname("sha1");
    unsigned int n;
    X509_digest(cert, digest, md, &n);
    std::cout << "sha1:" << to_hex(std::string((const char *)md, 20)) << std::endl;
    return true;
}

context_ptr on_tls_init(websocketpp::connection_hdl hdl) {
    namespace asio = websocketpp::lib::asio;

    context_ptr ctx = websocketpp::lib::make_shared<asio::ssl::context>(asio::ssl::context::sslv23);

    try {
        ctx->set_options(asio::ssl::context::default_workarounds |
                             asio::ssl::context::no_sslv2 |
                             asio::ssl::context::no_sslv3 |
                             asio::ssl::context::single_dh_use);

        //ctx->set_password_callback(bind(&get_password));
        ctx->set_verify_mode(boost::asio::ssl::verify_peer | boost::asio::ssl::verify_fail_if_no_peer_cert);
        ctx->use_certificate_chain_file("server.crt");
        ctx->use_private_key_file("server.key", asio::ssl::context::pem);
        //ctx->load_verify_file("client.crt");
        ctx->use_tmp_dh_file("dh.pem");
    } catch (std::exception& e) {
        std::cout << "Exception: " << e.what() << std::endl;
    }
    return ctx;
}

typedef websocketpp::lib::asio::ssl::stream<websocketpp::lib::asio::ip::tcp::socket> socket_type;

void on_socket_init(websocketpp::connection_hdl hdl, socket_type& sock)
{
    sock.set_verify_callback(bind(&on_verify_certificate, hdl, ::_1, ::_2));
}


/*bool generate_key()
{
    int             ret = 0;
    RSA             *r = NULL;
    BIGNUM          *bne = NULL;
    BIO             *bp_public = NULL, *bp_private = NULL;

    int             bits = 2048;
    unsigned long   e = RSA_F4;

    // 1. generate rsa key
    bne = BN_new();
    ret = BN_set_word(bne,e);
    if(ret != 1){
        goto free_all;
    }

    r = RSA_new();
    ret = RSA_generate_key_ex(r, bits, bne, NULL);
    if(ret != 1){
        goto free_all;
    }

    // 2. save public key
    bp_public = BIO_new_file("public.pem", "w+");
    ret = PEM_write_bio_RSAPublicKey(bp_public, r);
    if(ret != 1){
        goto free_all;
    }

    // 3. save private key
    bp_private = BIO_new_file("private.pem", "w+");
    ret = PEM_write_bio_RSAPrivateKey(bp_private, r, NULL, NULL, 0, NULL, NULL);

    // 4. free
free_all:

    BIO_free_all(bp_public);
    BIO_free_all(bp_private);
    RSA_free(r);
    BN_free(bne);

    return (ret == 1);
}*/

int main() {
    std::string sk, crt, digest;
    if(mkcert(2048, 1, 1000, sk, crt, digest))
    {
        std::cout << "Private Key:\n" << sk << std::endl;
        std::cout << "Certificate:\n" << crt << std::endl;
        std::cout << "sha1: " << digest << std::endl;
    }
    else
        std::cout << "error make cert" << std::endl;
    server echo_server;
    echo_server.init_asio();
    echo_server.set_socket_init_handler(bind(&on_socket_init,::_1,::_2));
    echo_server.set_message_handler(bind(&on_message,&echo_server,::_1,::_2));
    echo_server.set_http_handler(bind(&on_http,&echo_server,::_1));
    echo_server.set_tls_init_handler(bind(&on_tls_init,::_1));
    echo_server.listen(9002);
    echo_server.start_accept();
    echo_server.run();
}
