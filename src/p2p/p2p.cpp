#include "p2p.h"
#include "func.h"
#include "msg.h"
#include "util.h"
#include "mkcert.h"

#include <sodium.h>

#include "websocketpp/random/random_device.hpp"
#include "websocketpp/config/asio.hpp"
#include "websocketpp/config/asio_client.hpp"
#include "websocketpp/server.hpp"
#include "websocketpp/client.hpp"
#include <websocketpp/logger/levels.hpp>
#include <websocketpp/common/cpp11.hpp>
#include <websocketpp/common/stdint.hpp>
#include <websocketpp/common/time.hpp>

#include <boost/asio/ssl.hpp>
#include <boost/asio/deadline_timer.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/program_options.hpp>
#include <boost/algorithm/string.hpp>

#include <string>
#include <functional>
#include <memory>
#include <unordered_set>
#include <unordered_map>
#include <ctime>
#include <iostream>
#include <iomanip>

struct connection_meta_info {
    c2c::connection_ptr info;
};

namespace websocketpp {
namespace log {

    template <typename concurrency, typename names>
    class easylogging {
    public:
        easylogging<concurrency,names>(channel_type_hint::value h =
            channel_type_hint::access)
          : m_static_channels(0xffffffff)
          , m_dynamic_channels(0)
        {}

        easylogging<concurrency,names>(std::ostream * out)
          : m_static_channels(0xffffffff)
          , m_dynamic_channels(0)
        {}

        easylogging<concurrency,names>(level c, channel_type_hint::value h =
            channel_type_hint::access)
          : m_static_channels(c)
          , m_dynamic_channels(0)
        {}

        easylogging<concurrency,names>(level c, std::ostream * out)
          : m_static_channels(c)
          , m_dynamic_channels(0)
        {}

        /// Destructor
        ~easylogging<concurrency,names>()
        {}

        /// Copy constructor
        easylogging<concurrency,names>(easylogging<concurrency,names> const & other)
         : m_static_channels(other.m_static_channels)
         , m_dynamic_channels(other.m_dynamic_channels)
        {}

#ifdef _WEBSOCKETPP_DEFAULT_DELETE_FUNCTIONS_
        // no copy assignment operator because of const member variables
        easylogging<concurrency,names> & operator=(easylogging<concurrency,names> const &) = delete;
#endif // _WEBSOCKETPP_DEFAULT_DELETE_FUNCTIONS_

#ifdef _WEBSOCKETPP_MOVE_SEMANTICS_
        /// Move constructor
        easylogging<concurrency,names>(easylogging<concurrency,names> && other)
            : m_static_channels(other.m_static_channels)
            , m_dynamic_channels(other.m_dynamic_channels)
        {}

#ifdef _WEBSOCKETPP_DEFAULT_DELETE_FUNCTIONS_
        // no move assignment operator because of const member variables
        easylogging<concurrency,names> & operator=(easylogging<concurrency,names> &&) = delete;
#endif // _WEBSOCKETPP_DEFAULT_DELETE_FUNCTIONS_

#endif // _WEBSOCKETPP_MOVE_SEMANTICS_

        void set_ostream(std::ostream * out = &std::cout) {
        }

        void set_channels(level channels) {
            if (channels == names::none) {
                clear_channels(names::all);
                return;
            }

            scoped_lock_type lock(m_lock);
            m_dynamic_channels |= (channels & m_static_channels);
        }

        void clear_channels(level channels) {
            scoped_lock_type lock(m_lock);
            m_dynamic_channels &= ~channels;
        }

        /// Write a string message to the given channel
        /**
         * @param channel The channel to write to
         * @param msg The message to write
         */
        void write(level channel, std::string const & msg) {
            scoped_lock_type lock(m_lock);
            if (!this->dynamic_test(channel)) { return; }
            LOG(WARNING) << msg.c_str();
        }

        /// Write a cstring message to the given channel
        /**
         * @param channel The channel to write to
         * @param msg The message to write
         */
        void write(level channel, char const * msg) {
            scoped_lock_type lock(m_lock);
            if (!this->dynamic_test(channel)) { return; }
            LOG(WARNING) << msg;
        }

        _WEBSOCKETPP_CONSTEXPR_TOKEN_ bool static_test(level channel) const {
            return ((channel & m_static_channels) != 0);
        }

        bool dynamic_test(level channel) {
            return ((channel & m_dynamic_channels) != 0);
        }

    protected:
        typedef typename concurrency::scoped_lock_type scoped_lock_type;
        typedef typename concurrency::mutex_type mutex_type;
        mutex_type m_lock;

    private:
        // The timestamp does not include the time zone, because on Windows with the
        // default registry settings, the time zone would be written out in full,
        // which would be obnoxiously verbose.
        //
        // TODO: find a workaround for this or make this format user settable
        static std::ostream & timestamp(std::ostream & os) {
            std::time_t t = std::time(NULL);
            std::tm lt = lib::localtime(t);
            #ifdef _WEBSOCKETPP_PUTTIME_
                return os << std::put_time(&lt,"%Y-%m-%d %H:%M:%S");
            #else // Falls back to strftime, which requires a temporary copy of the string.
                char buffer[20];
                size_t result = std::strftime(buffer,sizeof(buffer),"%Y-%m-%d %H:%M:%S",&lt);
                return os << (result == 0 ? "Unknown" : buffer);
            #endif
        }

        level const m_static_channels;
        level m_dynamic_channels;
    };
} // log

namespace config {
    struct server : public core {
        typedef asio_tls type;
        typedef core base;

        typedef base::concurrency_type concurrency_type;

        typedef base::request_type request_type;
        typedef base::response_type response_type;

        typedef base::message_type message_type;
        typedef base::con_msg_manager_type con_msg_manager_type;
        typedef base::endpoint_msg_manager_type endpoint_msg_manager_type;

        typedef websocketpp::log::easylogging<concurrency_type, websocketpp::log::alevel> alog_type;
        typedef websocketpp::log::easylogging<concurrency_type, websocketpp::log::elevel> elog_type;

        typedef base::rng_type rng_type;

        struct transport_config : public base::transport_config {
            typedef type::concurrency_type concurrency_type;
            typedef server::alog_type alog_type;
            typedef server::elog_type elog_type;
            typedef type::request_type request_type;
            typedef type::response_type response_type;
            typedef websocketpp::transport::asio::tls_socket::endpoint socket_type;
        };
        typedef websocketpp::transport::asio::endpoint<transport_config> transport_type;
        typedef connection_meta_info connection_base;
    };

    struct client : public core_client {
        typedef asio_tls_client type;
        typedef core_client base;

        typedef base::concurrency_type concurrency_type;

        typedef base::request_type request_type;
        typedef base::response_type response_type;

        typedef base::message_type message_type;
        typedef base::con_msg_manager_type con_msg_manager_type;
        typedef base::endpoint_msg_manager_type endpoint_msg_manager_type;

        typedef websocketpp::log::easylogging<concurrency_type, websocketpp::log::alevel> alog_type;
        typedef websocketpp::log::easylogging<concurrency_type, websocketpp::log::elevel> elog_type;

        typedef base::rng_type rng_type;

        struct transport_config : public base::transport_config {
            typedef type::concurrency_type concurrency_type;
            typedef client::alog_type alog_type;
            typedef client::elog_type elog_type;
            typedef type::request_type request_type;
            typedef type::response_type response_type;
            typedef websocketpp::transport::asio::tls_socket::endpoint socket_type;
        };
        typedef websocketpp::transport::asio::endpoint<transport_config> transport_type;
        typedef connection_meta_info connection_base;
    };
}}

namespace c2c {
namespace p2p {

server::server(boost::asio::io_service& ios)
    : ios_(ios)
    , strand_(ios)
{
}

server::~server()
{
}

#define SRV_PARAM(srv)\
    (srv ".doc-dir", boost::program_options::value<std::string>(), "html/js doc directory")\
    (srv ".host", boost::program_options::value<std::string>(), "websocket host filter")\
    (srv ".port", boost::program_options::value<uint16_t>(), "websocket port listener")\
    (srv ".crt", boost::program_options::value<std::string>(), "filepath of ceritificate")\
    (srv ".key", boost::program_options::value<std::string>(), "filepath of private key")\
    (srv ".ca", boost::program_options::value<std::string>(), "filepath of CA ceritificate")\
    (srv ".map", boost::program_options::value<std::vector<std::string>>(), "http filepath fo url")

#define SRV_PARAMS() SRV_PARAM("srv-1")SRV_PARAM("srv-2")SRV_PARAM("srv-3")SRV_PARAM("srv-4")SRV_PARAM("srv-5")SRV_PARAM("srv-6")SRV_PARAM("srv-7")SRV_PARAM("srv-8")SRV_PARAM("srv-9")SRV_PARAM("srv-10")

void server::set_options_desc(boost::program_options::options_description_easy_init& options)
{
    options ("root-dir", boost::program_options::value<std::string>(), "root directory")
            ("host", boost::program_options::value<std::string>(), "websocket host filter")
            ("port", boost::program_options::value<uint16_t>(), "websocket port listener")
            ("crt", boost::program_options::value<std::string>(), "filepath of ceritificate")
            ("key", boost::program_options::value<std::string>(), "filepath of private key")
            ("ca", boost::program_options::value<std::string>(), "filepath of CA ceritificate")
            ("sk", boost::program_options::value<std::string>(), "secret key of node")
            ("pk", boost::program_options::value<std::string>(), "public key of node, is address")
            SRV_PARAMS();
}

namespace impl {

typedef websocketpp::lib::shared_ptr<websocketpp::lib::asio::ssl::context> context_ptr;

class server : public p2p::server, public std::enable_shared_from_this<server>
{
    typedef websocketpp::server<websocketpp::config::server> server_t;
    typedef websocketpp::client<websocketpp::config::client> client_t;
    typedef websocketpp::lib::asio::ssl::stream<websocketpp::lib::asio::ip::tcp::socket> stream_type;
    typedef websocketpp::random::none::int_generator<uint32_t> rng_type;

    binary_t sk_; // [crypto_sign_SECRETKEYBYTES];
    binary_t pk_; // [crypto_sign_PUBLICKEYBYTES];

    std::string host_;
    int port_;
    struct {
        std::string crt_;
        std::string key_;
        std::string ca_;
    } files;

    std::string crt_;
    std::string key_;
    std::string ca_;
    std::string digest_;
    binary_t x509_digest_;

    server_t ws_;
    client_t wc_;

    struct srv_config
    {
        srv_config() : port_(0) {}
        std::string host_;
        int port_;
        std::string crt_;
        std::string key_;
        std::string ca_;
        std::string doc_dir_;
        std::vector<std::vector<std::string>> map_;
        server_t ws_;
    };

    srv_config srv_[CON_SERVER_MAX];

    std::map<std::string, call_t> on_call_;
    std::map<std::string, call_r_t> on_call_r_;
    std::map<std::string, on_connection_t> on_open_, on_close_;

    struct reply_info_t
    {
        call_t func;
        boost::posix_time::ptime tout;
    };

    typedef std::map<var_t, reply_info_t> reply_map;
    reply_map reply_;

    typedef std::map<std::string, func_t> func_map;
    func_map func_;

    typedef std::map<std::string, func_r_t> func_r_map;
    func_r_map func_r_;

    std::string root_dir_;

    std::unordered_map<std::string, std::string> mime_;
    void init_mimetypes();

    connection_ptr get_con_from_hdl(CON_SRC src, websocketpp::connection_hdl hdl);

    context_ptr on_srv_tls_init(websocketpp::connection_hdl hdl);
    context_ptr on_srv_tls_init_x(CON_SRC src, websocketpp::connection_hdl hdl);
    context_ptr on_cli_tls_init(websocketpp::connection_hdl hdl);

    void on_socket_init(CON_SRC src, websocketpp::connection_hdl hdl, stream_type& sock);
    bool on_verify_certificate(CON_SRC src, websocketpp::connection_hdl hdl, bool preverified, boost::asio::ssl::verify_context& ctx);
    void on_open(CON_SRC con, websocketpp::connection_hdl hdl);
    void on_close(CON_SRC con, websocketpp::connection_hdl hdl);
    bool on_validate(CON_SRC con, websocketpp::connection_hdl);
    void on_http(CON_SRC src, websocketpp::connection_hdl hdl);
    void on_message(CON_SRC con, websocketpp::connection_hdl hdl, server_t::message_ptr msg);

    bool on_call(connection_ptr con, const std::string& method, const var_t& params);
    bool on_call_r(connection_ptr con, const std::string& method, const var_t& params, call_t reply);

    bool do_get_identify(connection_ptr con);
    void on_get_identify(connection_ptr con, binary_t tn, bool with_digest, response_t response);

    void do_send(connection_ptr con, const var_t& id, const std::string& method, const var_t& params);

    void do_on_open(connection_ptr con);

public:
    server(boost::asio::io_service& ios, boost::program_options::variables_map& vm);
    ~server();

    connection_ptr connect(const std::vector<std::string>& proto, const std::string& uri, const std::string& ca = std::string());

    void close(connection_ptr);

    void call(const std::string& method, var_t params, const std::vector<connection_ptr>& peers = std::vector<connection_ptr>());
    void call(const std::string& method, var_t params, call_t reply, const std::vector<connection_ptr>& peers = std::vector<connection_ptr>());

    bool start();

    void join(const std::string&, const on_connection_t&, const on_connection_t&, const call_t&, const call_r_t&);
    void leave(const std::string&);

    void sign(const std::string& data, std::string& sig);

    std::string self_id()
    {
        if(pk_.size() == crypto_sign_PUBLICKEYBYTES)
        {
            char pk[crypto_sign_PUBLICKEYBYTES * 2 + 1];
            sodium_bin2hex(pk, crypto_sign_PUBLICKEYBYTES * 2 + 1, pk_.data(), crypto_sign_PUBLICKEYBYTES);
            return pk;
        }
        return std::string();
    }
};

server::server(boost::asio::io_service& ios, boost::program_options::variables_map& vm)
    : p2p::server(ios)
    , host_("0.0.0.0")
    , port_(12011)
    , root_dir_(".")
{
    bool ka = false;
    if(vm.count("sk") > 0 && vm.count("pk") > 0)
    {
        const std::string& sk = vm["sk"].as<std::string>().c_str();
        const std::string& pk = vm["pk"].as<std::string>().c_str();
        if(sk.length() == crypto_sign_SECRETKEYBYTES * 2 && pk.length() == crypto_sign_PUBLICKEYBYTES * 2)
        {
            sk_.resize(crypto_sign_SECRETKEYBYTES);
            sodium_hex2bin(sk_.data(), crypto_sign_SECRETKEYBYTES, sk.data(), sk.length(), nullptr, nullptr, nullptr);
            pk_.resize(crypto_sign_PUBLICKEYBYTES);
            sodium_hex2bin(pk_.data(), crypto_sign_PUBLICKEYBYTES, pk.data(), pk.length(), nullptr, nullptr, nullptr);
            ka = true;
        }
    }

    if(!ka)
    {
        sk_.resize(crypto_sign_SECRETKEYBYTES);
        pk_.resize(crypto_sign_PUBLICKEYBYTES);
        if(crypto_sign_keypair(pk_.data(), sk_.data()) == 0)
        {
            char pk[crypto_sign_PUBLICKEYBYTES * 2 + 1];
            char sk[crypto_sign_SECRETKEYBYTES * 2 + 1];
            sodium_bin2hex(pk, crypto_sign_PUBLICKEYBYTES * 2 + 1, pk_.data(), crypto_sign_PUBLICKEYBYTES);
            sodium_bin2hex(sk, crypto_sign_SECRETKEYBYTES * 2 + 1, sk_.data(), crypto_sign_SECRETKEYBYTES);
            LOG(WARNING) << "pk: " << pk;
            LOG(WARNING) << "sk: " << sk;
        }
        else
        {
            LOG(ERROR) << "error create sign key pair";
        }
    }

    if(vm.count("root-dir") > 0) root_dir_ = path_normalize(vm["root-dir"].as<std::string>());
    if(vm.count("host") > 0) host_ = vm["host"].as<std::string>().c_str();
    if(vm.count("port") > 0) port_ = vm["port"].as<uint16_t>();
    if(vm.count("crt") > 0) files.crt_ = filepath_normalize(root_dir_, vm["crt"].as<std::string>().c_str());
    if(vm.count("key") > 0) files.key_ = filepath_normalize(root_dir_, vm["key"].as<std::string>().c_str());
    if(vm.count("ca") > 0) files.ca_ = filepath_normalize(root_dir_, vm["ca"].as<std::string>().c_str());

    for(size_t n=0; n<CON_SERVER_MAX; n++)
    {
        std::string srvn("srv-"); srvn += std::to_string(n+1); srvn += ".";
        if(vm.count(srvn+"port") > 0)
        {
            srv_config& cfg = srv_[n];
            if(vm.count(srvn+"doc-dir") > 0) cfg.doc_dir_ = path_normalize(root_dir_, vm[srvn+"doc-dir"].as<std::string>());
            if(vm.count(srvn+"host") > 0) cfg.host_ = vm[srvn+"host"].as<std::string>().c_str();
            if(vm.count(srvn+"port") > 0) cfg.port_ = vm[srvn+"port"].as<uint16_t>();
            if(vm.count(srvn+"crt") > 0) cfg.crt_ = filepath_normalize(root_dir_, vm[srvn+"crt"].as<std::string>().c_str());
            if(vm.count(srvn+"key") > 0) cfg.key_ = filepath_normalize(root_dir_, vm[srvn+"key"].as<std::string>().c_str());
            if(vm.count(srvn+"ca") > 0) cfg.ca_ = filepath_normalize(root_dir_, vm[srvn+"ca"].as<std::string>().c_str());
            if(vm.count(srvn+"map") > 0)
            {
                for(const std::string& n : vm[srvn+"map"].as<std::vector<std::string>>())
                {
                    cfg.map_.resize(cfg.map_.size()+1);
                    std::vector<std::string>& m = cfg.map_.back();
                    boost::split(m, n, boost::is_any_of(" "), boost::token_compress_on);
                    if(m.size()>1)
                        m[1] = path_normalize((cfg.doc_dir_.empty() ? root_dir_ : cfg.doc_dir_), m[1]);
                }
            }
        }
    }

    init_mimetypes();
}

server::~server()
{
}

bool server::start()
{
    try
    {
        // methods map
        func_r_["get_identify"] = wrap_r(&server::on_get_identify, this);

        if(!mkcert(2048, 0, 10000, key_, crt_, digest_))
        {
            LOG(ERROR) << "error make certificate";
            return false;
        }

        hex2bin(digest_, x509_digest_);

        ws_.init_asio(&ios_);
        ws_.set_tls_init_handler(websocketpp::lib::bind(
            &server::on_srv_tls_init, shared_from_this(), websocketpp::lib::placeholders::_1));
        if(files.ca_.length()==0)
            ws_.set_socket_init_handler(websocketpp::lib::bind(
                &server::on_socket_init, shared_from_this(), CON_SERVER, websocketpp::lib::placeholders::_1, websocketpp::lib::placeholders::_2));
        ws_.set_open_handler(websocketpp::lib::bind(
            &server::on_open, shared_from_this(), CON_SERVER, websocketpp::lib::placeholders::_1));
        ws_.set_close_handler(websocketpp::lib::bind(
            &server::on_close, shared_from_this(), CON_SERVER, websocketpp::lib::placeholders::_1));
        ws_.set_message_handler(websocketpp::lib::bind(
            &server::on_message, shared_from_this(), CON_SERVER, websocketpp::lib::placeholders::_1, websocketpp::lib::placeholders::_2));
        ws_.set_validate_handler(websocketpp::lib::bind(
            &server::on_validate, shared_from_this(), CON_SERVER, websocketpp::lib::placeholders::_1));
        ws_.listen(host_, std::to_string(port_));
        ws_.start_accept();

        wc_.init_asio(&ios_);
        wc_.set_tls_init_handler(websocketpp::lib::bind(
            &server::on_cli_tls_init, shared_from_this(), websocketpp::lib::placeholders::_1));
        wc_.set_socket_init_handler(websocketpp::lib::bind(
            &server::on_socket_init, shared_from_this(), CON_CLIENT, websocketpp::lib::placeholders::_1, websocketpp::lib::placeholders::_2));
        wc_.set_open_handler(websocketpp::lib::bind(
            &server::on_open, shared_from_this(), CON_CLIENT, websocketpp::lib::placeholders::_1));
        wc_.set_close_handler(websocketpp::lib::bind(
            &server::on_close, shared_from_this(), CON_CLIENT, websocketpp::lib::placeholders::_1));
        wc_.set_message_handler(websocketpp::lib::bind(
            &server::on_message, shared_from_this(), CON_CLIENT, websocketpp::lib::placeholders::_1, websocketpp::lib::placeholders::_2));
        wc_.set_validate_handler(websocketpp::lib::bind(
            &server::on_validate, shared_from_this(), CON_CLIENT, websocketpp::lib::placeholders::_1));

        for(size_t n=0; n<CON_SERVER_MAX; n++)
        {
            srv_config& cfg = srv_[n];
            if(cfg.port_)
            {
                CON_SRC src = CON_SRC(n);
                cfg.ws_.init_asio(&ios_);
                cfg.ws_.set_tls_init_handler(websocketpp::lib::bind(
                    &server::on_srv_tls_init_x, shared_from_this(), src, websocketpp::lib::placeholders::_1));
                cfg.ws_.set_open_handler(websocketpp::lib::bind(
                    &server::on_open, shared_from_this(), src, websocketpp::lib::placeholders::_1));
                cfg.ws_.set_close_handler(websocketpp::lib::bind(
                    &server::on_close, shared_from_this(), src, websocketpp::lib::placeholders::_1));
                if(cfg.map_.size() > 0)
                    cfg.ws_.set_http_handler(websocketpp::lib::bind(
                        &server::on_http, shared_from_this(), src, websocketpp::lib::placeholders::_1));
                cfg.ws_.set_message_handler(websocketpp::lib::bind(
                    &server::on_message, shared_from_this(), src, websocketpp::lib::placeholders::_1, websocketpp::lib::placeholders::_2));
                cfg.ws_.set_validate_handler(websocketpp::lib::bind(
                    &server::on_validate, shared_from_this(), src, websocketpp::lib::placeholders::_1));
                cfg.ws_.listen(cfg.host_, std::to_string(cfg.port_));
                cfg.ws_.start_accept();
            }
        }
        return true;
    }
    catch(const websocketpp::exception& e)
    {
        LOG(ERROR) << e.what();
    }
    return false;
}

connection_ptr server::get_con_from_hdl(CON_SRC src, websocketpp::connection_hdl hdl)
{
    connection_ptr con;
    switch(src)
    {
    case CON_SERVER: con = ws_.get_con_from_hdl(hdl)->info; break;
    case CON_CLIENT: con = wc_.get_con_from_hdl(hdl)->info; break;
    default: con = srv_[src].ws_.get_con_from_hdl(hdl)->info; break;
    }

    if(!con)
    {
        con = std::make_shared<connection_t>();
        con->hdl = hdl;
        con->con = src;
        con->type = CON_UNKNOWN;
        switch(src)
        {
        case CON_SERVER:
            {
                auto wc = ws_.get_con_from_hdl(hdl);
                con->proto = wc ->get_requested_subprotocols();
                wc->info = con;
            }
            break;
        case CON_CLIENT:
            {
                auto wc = wc_.get_con_from_hdl(hdl);
                con->proto = wc ->get_requested_subprotocols();
                wc->info = con;
            }
            break;
        default:
            {
                auto wc = srv_[src].ws_.get_con_from_hdl(hdl);
                con->proto = wc ->get_requested_subprotocols();
                wc->info = con;
            }
            break;
        }
    }
    return con;
}

void server::on_socket_init(CON_SRC src, websocketpp::connection_hdl hdl, stream_type& socket)
{
    connection_ptr con = get_con_from_hdl(src, hdl);
    if(con->ca.empty())
        socket.set_verify_callback(websocketpp::lib::bind(&server::on_verify_certificate, shared_from_this(), src, hdl, websocketpp::lib::placeholders::_1, websocketpp::lib::placeholders::_2));
}

bool server::on_verify_certificate(CON_SRC src, websocketpp::connection_hdl hdl, bool preverified, boost::asio::ssl::verify_context& ctx)
{
    int depth = X509_STORE_CTX_get_error_depth(ctx.native_handle());
    if (depth > 0)
        return true;
    connection_ptr con = get_con_from_hdl(src, hdl);
    X509* crt = X509_STORE_CTX_get_current_cert(ctx.native_handle());
    const EVP_MD *digest = EVP_get_digestbyname("sha1");
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int n;
    X509_digest(crt, digest, md, &n);
    con->x509_digest.assign(md, md+20);
    //LOG(WARNING) << "certificate sha1 digest: " << bin2hex(con->x509_digest.data(), con->x509_digest.size());
    return true;
}

context_ptr server::on_srv_tls_init(websocketpp::connection_hdl hdl)
{
    context_ptr ctx(new boost::asio::ssl::context(boost::asio::ssl::context::sslv23));
    try
    {
        ctx->set_options(boost::asio::ssl::context::default_workarounds |
                         boost::asio::ssl::context::no_sslv2 |
                         boost::asio::ssl::context::no_sslv3 |
                         boost::asio::ssl::context::single_dh_use);
        ctx->set_verify_mode(boost::asio::ssl::verify_peer|boost::asio::ssl::verify_fail_if_no_peer_cert);
        if(files.crt_.length()>0 && files.key_.length()>0)
        {
            ctx->use_certificate_chain_file(files.crt_);
            ctx->use_private_key_file(files.key_, boost::asio::ssl::context::pem);
            if(files.ca_.length()>0)
                ctx->load_verify_file(files.ca_);
        }
        else
        {
            ctx->use_certificate_chain(boost::asio::buffer(crt_.data(), crt_.length()));
            ctx->use_private_key(boost::asio::buffer(key_.data(), key_.length()), boost::asio::ssl::context::pem);
        }
        const std::string& params = DH_params();
        ctx->use_tmp_dh(boost::asio::buffer(params.data(), params.length()));
    }
    catch (std::exception& e)
    {
        LOG(ERROR) << e.what();
    }
    return ctx;
}

context_ptr server::on_srv_tls_init_x(CON_SRC src, websocketpp::connection_hdl hdl)
{
    srv_config& cfg = srv_[src];
    context_ptr ctx(new boost::asio::ssl::context(boost::asio::ssl::context::sslv23));
    try
    {
        ctx->set_options(boost::asio::ssl::context::default_workarounds |
                         boost::asio::ssl::context::no_sslv2 |
                         boost::asio::ssl::context::no_sslv3 |
                         boost::asio::ssl::context::single_dh_use);
        boost::asio::ssl::verify_mode m = boost::asio::ssl::verify_none;
        if(cfg.map_.size()==0)
        {
            m |= boost::asio::ssl::verify_fail_if_no_peer_cert;
            if(cfg.ca_.length()>0)
            {
                m |= boost::asio::ssl::verify_peer;
                ctx->load_verify_file(cfg.ca_);
            }
        }
        ctx->set_verify_mode(m);
        ctx->use_certificate_chain_file(cfg.crt_);
        ctx->use_private_key_file(cfg.key_, boost::asio::ssl::context::pem);
        const std::string& params = DH_params();
        ctx->use_tmp_dh(boost::asio::buffer(params.data(), params.length()));
    }
    catch (std::exception& e)
    {
        LOG(ERROR) << e.what();
    }
    return ctx;
}

context_ptr server::on_cli_tls_init(websocketpp::connection_hdl hdl)
{
    connection_ptr con = wc_.get_con_from_hdl(hdl)->info;
    context_ptr ctx(new boost::asio::ssl::context(boost::asio::ssl::context::sslv23));
    try
    {
        ctx->set_options(boost::asio::ssl::context::default_workarounds |
                         boost::asio::ssl::context::no_sslv2 |
                         boost::asio::ssl::context::no_sslv3 |
                         boost::asio::ssl::context::single_dh_use);
        ctx->set_verify_mode(boost::asio::ssl::verify_peer|boost::asio::ssl::verify_fail_if_no_peer_cert);
        if(files.crt_.size()>0 && files.key_.size())
        {
            ctx->use_certificate_chain_file(files.crt_);
            ctx->use_private_key_file(files.key_, boost::asio::ssl::context::pem);
        }
        else
        {
            ctx->use_certificate_chain(boost::asio::buffer(crt_.data(), crt_.length()));
            ctx->use_private_key(boost::asio::buffer(key_.data(), key_.length()), boost::asio::ssl::context::pem);
        }
    }
    catch (std::exception& e)
    {
        LOG(ERROR) << e.what();
    }
    return ctx;
}

void server::on_open(CON_SRC src, websocketpp::connection_hdl hdl)
{
    connection_ptr con = get_con_from_hdl(src, hdl);

    if(con->type != CON_UNKNOWN)
        do_get_identify(con);

    //for(auto p : con->proto)
    //{
        //auto n = on_open_.find(p);
        //if(n != on_open_.end()) n->second(con);
    //}
}

void server::do_on_open(connection_ptr con)
{
    for(auto p : con->proto)
    {
        auto n = on_open_.find(p);
        if(n != on_open_.end()) n->second(con);
    }
}

void server::on_close(CON_SRC src, websocketpp::connection_hdl hdl)
{
    connection_ptr con = get_con_from_hdl(src, hdl);

    for(auto p : con->proto)
    {
        auto n = on_close_.find(p);
        if(n != on_close_.end()) n->second(con);
    }
}

bool server::on_validate(CON_SRC src, websocketpp::connection_hdl hdl)
{
    connection_ptr con = get_con_from_hdl(src, hdl);

    //if(con->proto.size() == 0)
        //return false;

    for(auto p : con->proto)
    {
        auto n = on_open_.find(p);
        if(n == on_close_.end())
            return false;
    }

    return true;
}

void server::on_http(CON_SRC src, websocketpp::connection_hdl hdl)
{
    srv_config& cfg = srv_[src];
    server_t::connection_ptr con = cfg.ws_.get_con_from_hdl(hdl);

    std::ifstream file;
    std::string response, filepath;

    std::string filename = con->get_resource();
    size_t n = filename.find('#');
    if(n != std::string::npos)
        filename = filename.substr(0, n);
    n = filename.find('?');
    if(n != std::string::npos)
        filename = filename.substr(0, n);

    if (filename == "/")
        filename = "/index.html";

    for(auto u=cfg.map_.begin(); u<cfg.map_.end(); u++)
    {
        const std::string& res = (*u)[0];
        if(std::string::npos != filename.find(res))
        {
            filepath += (*u)[1]+filename.substr(res.length());
            break;
        }
    }

    file.open(filepath.c_str(), std::ios::in);
    if (!file) {
        // 404 error
        std::stringstream ss;

        ss << "<!doctype html><html><head>"
           << "<title>Error 404 (Resource not found)</title><body>"
           << "<h1>Error 404</h1>"
           << "<p>The requested URL " << filename << " was not found on this server.</p>"
           << "</body></head></html>";

        con->set_body(ss.str());
        con->set_status(websocketpp::http::status_code::not_found);
        return;
    }

    file.seekg(0, std::ios::end);
    response.reserve(file.tellg());
    file.seekg(0, std::ios::beg);

    response.assign((std::istreambuf_iterator<char>(file)),
                    std::istreambuf_iterator<char>());

    std::string ext;
    size_t pt=filename.rfind(".");
    if(pt<std::string::npos)
        for(pt++;pt<filename.length(); pt++)
            ext.push_back(char(::tolower(filename[pt])));
    auto m =  mime_.find(ext.c_str());
    con->append_header("Content-Type", (m != mime_.end() ? m->second : "text/plain"));

    con->set_body(response);
    con->set_status(websocketpp::http::status_code::ok);
}

void server::on_message(CON_SRC src, websocketpp::connection_hdl hdl, server_t::message_ptr msg_ptr)
{
    try
    {
        connection_ptr con = get_con_from_hdl(src, hdl);

        CON_TYPE con_type = con->type;
        if(con_type == CON_UNKNOWN)
        {
            if (msg_ptr->get_opcode() == websocketpp::frame::opcode::text)
                con_type = CON_JSON;
            else
                con_type = CON_MSGPACK;
            con->type = con_type;
            do_get_identify(con);
        }

        std::string payload = msg_ptr->get_payload();
        //LOG(WARNING) << payload;
        var_t msg;

        switch(con_type)
        {
        case CON_JSON: msg = json2var(payload); break;
        case CON_MSGPACK: msg = pack2var(payload); break;
        case CON_UNKNOWN:
            LOG(ERROR) << "Unknown request format type";
            return;
        }

        std::map<std::string, item_t>& m = *mpark::get<map_t>(msg);

        auto it_jsonrpc = m.find("jsonrpc");
        if(it_jsonrpc == m.end())
        {
            LOG(ERROR) << "Error: jsonrpc version not found";
            return;
        }

        std::string& jsonrpc = mpark::get<std::string>(it_jsonrpc->second.value);

        if(jsonrpc != "2.0")
        {
            LOG(ERROR) << "Error jsonrpc version: " << jsonrpc;
            return;
        }

        auto it_id = m.find("id");
        auto it_method = m.find("method");
        auto it_params = m.find("params");
        auto it_result = m.find("result");
        auto it_error = m.find("error");

        if(it_method == m.end())
        {
            if(it_id == m.end())
            {
                LOG(ERROR) << "error, reply id not found";
                return;
            }

            auto it_reply = reply_.find(it_id->second.value);
            if(it_reply == reply_.end())
            {
                LOG(ERROR) << "error, reply with id: " << var2json(it_id->second.value) << " is not found";
                return;
            }

            if(it_result != m.end())
                it_reply->second.func(con, "result", it_result->second.value);
            else if(it_error != m.end())
                it_reply->second.func(con, "error", it_error->second.value);
        }
        else if(it_id != m.end())
        {
            std::string& method = mpark::get<std::string>(it_method->second.value);

            struct CB {
                std::shared_ptr<server> srv;
                var_t id;
                bool on(connection_ptr con , std::string opt, var_t params) { srv->do_send(con, id, opt, params); return true; }
            };

            std::shared_ptr<CB> cb(new CB());
            cb->srv = shared_from_this();
            cb->id = it_id->second.value;
            call_t r = std::bind(&CB::on, cb, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3);

            var_t params = nil_t(nullptr);
            if(it_params != m.end())
                params = it_params->second.value;

            if(!on_call_r(con, method, params, r))
            {
                for(auto p : con->proto)
                {
                    auto n = on_call_r_.find(p);
                    if(n != on_call_r_.end())
                        n->second(con, method, params, r);
                }
            }
        }
        else
        {
            std::string& method = mpark::get<std::string>(it_method->second.value);

            var_t params = nil_t(nullptr);
            if(it_params != m.end())
                params = it_params->second.value;

            if(!on_call(con, method, params))
            {
                for(auto p : con->proto)
                {
                    auto n = on_call_.find(p);
                    if(n != on_call_.end())
                        n->second(con, method, params);
                }
            }
        }
    }
    catch(const std::exception& e)
    {
        LOG(ERROR) << e.what();
    }
}

bool server::on_call(connection_ptr con, const std::string& method, const var_t& params)
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

bool server::on_call_r(connection_ptr con, const std::string& method, const var_t& params, call_t reply)
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

bool server::do_get_identify(connection_ptr con)
{
    if(con->type == CON_UNKNOWN)
        return false;

    struct __reply__
    {
        std::shared_ptr<server> s_;
        binary_t m_;
        func_t f_;

        __reply__(const std::shared_ptr<server>& s)
            : s_(s)
            , f_(wrap(&__reply__::on, this))
        {}

        bool __on(connection_ptr con, const std::string& meth, const var_t& data)
        {
            if(meth == "error")
            {
                std::string log = "error";
                map_t m = mpark::get<map_t>(data);
                auto it_code = m->find(" code");
                if(it_code != m->end())
                    log += "code: " + std::to_string(mpark::get<int>(it_code->second.value));
                auto it_message = m->find("message");
                if(it_message != m->end())
                    log += " message: " + mpark::get<std::string>(it_message->second.value);
                LOG(ERROR) << log;
            }
            else
                f_(con, data);
            return true;
        }

        void on(connection_ptr con, binary_t pk, binary_t sg, vec_t proto)
        {
            if(pk.size() != crypto_sign_PUBLICKEYBYTES || sg.size() != crypto_sign_BYTES)
            {
                const char *err = "error get_identify respose";
                LOG(ERROR) << err;
                s_->close(con);
                return;
            }

            if(0 != crypto_sign_verify_detached(sg.data(), m_.data(), m_.size(), pk.data()))
            {
                const char *err = "error verify of get_identify respose\nm: ";
                LOG(ERROR) << err << bin2hex(m_.data(), m_.size());
                s_->close(con);
                return;
            }

            con->id = pk;
            for(auto n=proto->begin(); n<proto->end(); n++)
                con->proto.push_back(mpark::get<std::string>(n->value));

            LOG(WARNING) << "success identify node id: " << bin2hex(pk.data(), pk.size());

            s_->do_on_open(con);
        }
    };

    std::shared_ptr<__reply__> reply(new __reply__(shared_from_this()));

    // token
    binary_t tn; tn.resize(16);
    ::randombytes(tn.data(), 16);

    reply->m_.assign(tn.begin(), tn.end());

    bool with_digest = false;
    if(!con->x509_digest.empty())
    {
        reply->m_.insert(reply->m_.end(), con->x509_digest.begin(), con->x509_digest.end());
        with_digest = true;
    }

    var_t params = to_var(tn, with_digest);

    std::vector<connection_ptr> peers;
    peers.push_back(con);

    call_t r = std::bind(&__reply__::__on, reply,
        std::placeholders::_1, std::placeholders::_2, std::placeholders::_3);

    call("get_identify", params, r, peers);

    return true;
}

void server::on_get_identify(connection_ptr con, binary_t tn, bool with_digest, response_t response)
{
    binary_t buf;

    buf.insert(buf.end(), tn.begin(), tn.end());
    if(with_digest)
        buf.insert(buf.end(), x509_digest_.begin(), x509_digest_.end());

    unsigned long long l;
    binary_t sm; sm.resize(crypto_sign_BYTES);

    if(0 == crypto_sign_detached(sm.data(), &l, buf.data(), buf.size(), sk_.data()))
    {
        //LOG(WARNING) << "sign m: " << bin2hex(buf.data(), buf.size());
        vec_t proto( new std::vector<item_t>() );
        for(auto n: con->proto) proto->push_back({n});
        response(pk_, sm, proto);
    }
    else
    {
        std::string err = "error sign of data";
        response.error(err);
        LOG(ERROR) << err;
    }
}

void server::sign(const std::string& data, std::string& sig)
{
    unsigned long long l = 0;
    sig.resize(crypto_sign_BYTES);

    if(0 != crypto_sign_detached(
        (uint8_t *)sig.data(), &l, (uint8_t *)data.data(), data.size(), sk_.data()))
    {
        sig.clear();
    }
}

void server::do_send(connection_ptr con, const var_t& id, const std::string& method, const var_t& params)
{
    var_t msg = std::make_shared<std::map<std::string, item_t>>();
    std::map<std::string, item_t>& m = *mpark::get<map_t>(msg);

    m["jsonrpc"].value = std::string("2.0");

    if(type(id) != NIL)
        m["id"].value = id;

    if(method == "error" || method == "result")
    {
        m[method].value = params;
    }
    else
    {
        m["method"].value = method;
        m["params"].value = params;
    }

    std::string data;
    websocketpp::frame::opcode::value op;

    if(con->type == CON_MSGPACK)
    {
        var2pack(msg, data);
        op = websocketpp::frame::opcode::binary;
    }
    else if(con->type == CON_JSON)
    {
        var2json(msg, data);
        op = websocketpp::frame::opcode::text;
        //LOG(WARNING) << data;
    }
    else
    {
        LOG(ERROR) << "unknown connection type, json or msgpack";
        return;
    }

    websocketpp::lib::error_code ec;
    switch(con->con)
    {
    case CON_SERVER: ws_.send(con->hdl, data, op, ec); break;
    case CON_CLIENT: wc_.send(con->hdl, data, op, ec); break;
    default: srv_[con->con].ws_.send(con->hdl, data, op, ec); break;
    }
    if(ec)
        LOG(ERROR) << "send failed because: " << ec.value() << "(" << ec.message() << ")";
}

connection_ptr server::connect(const std::vector<std::string>& proto, const std::string& uri, const std::string& ca)
{
    websocketpp::lib::error_code ec;
    client_t::connection_ptr cli_con = wc_.get_connection(uri, ec);

    if(ec)
    {
        LOG(ERROR) << "Connect initialization error: " << ec.message() << std::endl;
        return connection_ptr();
    }

    connection_ptr con = std::make_shared<connection_t>();

    con->uri = uri;
    con->ca = ca;
    con->hdl = cli_con->get_handle();
    con->proto = proto;
    con->con = CON_CLIENT;
    con->type = CON_MSGPACK;
    cli_con->info = con;

    for(auto p : proto)
        cli_con->add_subprotocol(p);

    wc_.connect(cli_con);

    return con;
}

void server::close(connection_ptr con)
{
    std::string reason("OK");
    websocketpp::lib::error_code ec;
    switch(con->con)
    {
    case CON_SERVER: ws_.close(con->hdl, websocketpp::close::status::normal, reason, ec); break;
    case CON_CLIENT: wc_.close(con->hdl, websocketpp::close::status::normal, reason, ec); break;
    default: srv_[con->con].ws_.close(con->hdl, websocketpp::close::status::normal, reason, ec); break;
    }
    if(ec)
        LOG(ERROR) << "send failed because: " << ec.value() << "(" << ec.message() << ")";
}

void server::call(const std::string& method, var_t params, const std::vector<connection_ptr>& peers)
{
    for(auto n = peers.begin(); n!=peers.end(); n++)
        do_send(*n, nil_t(nullptr), method, params);
}

void server::call(const std::string& method, var_t params, call_t reply, const std::vector<connection_ptr>& peers)
{
    CON_TYPE t_id = CON_MSGPACK;
    for(auto n = peers.begin(); n!=peers.end(); n++)
    {
        if((*n)->type == CON_JSON)
        {
            t_id = CON_JSON;
            break;
        }
    }

    var_t id;

    binary_t rnd; rnd.resize(16);
    ::randombytes(rnd.data(), 16);

    if(t_id == CON_JSON)
        id = bin2hex(rnd.data(), rnd.size());
    else
        id = rnd;

    reply_info_t& info = reply_[id];
    info.func = reply;
    info.tout = boost::posix_time::microsec_clock::universal_time() + boost::posix_time::seconds(15);

    for(auto n = peers.begin(); n!=peers.end(); n++)
        do_send(*n, id, method, params);
}

void server::join(const std::string& proto, const on_connection_t& on_open, const on_connection_t& on_close, const call_t& on_call, const call_r_t& on_call_r)
{
    on_open_[proto] = on_open;
    on_close_[proto] = on_close;
    on_call_[proto] = on_call;
    on_call_r_[proto] = on_call_r;
}

void server::leave(const std::string& proto)
{
    on_open_.erase(proto);
    on_close_.erase(proto);
    on_call_.erase(proto);
    on_call_r_.erase(proto);
}

void server::init_mimetypes()
{
    mime_["3gp"] = "video/3gpp";
    mime_["a"] = "application/octet-stream";
    mime_["ai"] = "application/postscript";
    mime_["aif"] = "audio/x-aiff";
    mime_["aiff"] = "audio/x-aiff";
    mime_["asc"] = "application/pgp-signature";
    mime_["asf"] = "video/x-ms-asf";
    mime_["asm"] = "text/x-asm";
    mime_["asx"] = "video/x-ms-asf";
    mime_["atom"] = "application/atom+xml";
    mime_["au"] = "audio/basic";
    mime_["avi"] = "video/x-msvideo";
    mime_["bat"] = "application/x-msdownload";
    mime_["bin"] = "application/octet-stream";
    mime_["bmp"] = "image/bmp";
    mime_["bz2"] = "application/x-bzip2";
    mime_["c"] = "text/x-c";
    mime_["cab"] = "application/vnd.ms-cab-compressed";
    mime_["cc"] = "text/x-c";
    mime_["chm"] = "application/vnd.ms-htmlhelp";
    mime_["class"] = "application/octet-stream";
    mime_["com"] = "application/x-msdownload";
    mime_["conf"] = "text/plain";
    mime_["cpp"] = "text/x-c";
    mime_["crt"] = "application/x-x509-ca-cert";
    mime_["css"] = "text/css";
    mime_["csv"] = "text/csv";
    mime_["cxx"] = "text/x-c";
    mime_["deb"] = "application/x-debian-package";
    mime_["der"] = "application/x-x509-ca-cert";
    mime_["diff"] = "text/x-diff";
    mime_["djv"] = "image/vnd.djvu";
    mime_["djvu"] = "image/vnd.djvu";
    mime_["dll"] = "application/x-msdownload";
    mime_["dmg"] = "application/octet-stream";
    mime_["doc"] = "application/msword";
    mime_["dot"] = "application/msword";
    mime_["dtd"] = "application/xml-dtd";
    mime_["dvi"] = "application/x-dvi";
    mime_["ear"] = "application/java-archive";
    mime_["eml"] = "message/rfc822";
    mime_["eps"] = "application/postscript";
    mime_["exe"] = "application/x-msdownload";
    mime_["f"] = "text/x-fortran";
    mime_["f77"] = "text/x-fortran";
    mime_["f90"] = "text/x-fortran";
    mime_["flv"] = "video/x-flv";
    mime_["for"] = "text/x-fortran";
    mime_["gem"] = "application/octet-stream";
    mime_["gemspec"] = "text/x-script.ruby";
    mime_["gif"] = "image/gif";
    mime_["gz"] = "application/x-gzip";
    mime_["h"] = "text/x-c";
    mime_["hh"] = "text/x-c";
    mime_["htm"] = "text/html";
    mime_["html"] = "text/html";
    mime_["ico"] = "image/vnd.microsoft.icon";
    mime_["ics"] = "text/calendar";
    mime_["ifb"] = "text/calendar";
    mime_["iso"] = "application/octet-stream";
    mime_["jar"] = "application/java-archive";
    mime_["java"] = "text/x-java-source";
    mime_["jnlp"] = "application/x-java-jnlp-file";
    mime_["jpeg"] = "image/jpeg";
    mime_["jpg"] = "image/jpeg";
    mime_["js"] = "application/javascript";
    mime_["json"] = "application/json";
    mime_["less"] = "text/css";
    mime_["log"] = "text/plain";
    mime_["lua"] = "text/x-lua";
    mime_["luac"] = "application/x-lua-bytecode";
    mime_["m3u"] = "audio/x-mpegurl";
    mime_["m4v"] = "video/mp4";
    mime_["man"] = "text/troff";
    mime_["manifest"] = "text/cache-manifest";
    mime_["markdown"] = "text/markdown";
    mime_["mathml"] = "application/mathml+xml";
    mime_["mbox"] = "application/mbox";
    mime_["mdoc"] = "text/troff";
    mime_["md"] = "text/markdown";
    mime_["me"] = "text/troff";
    mime_["mid"] = "audio/midi";
    mime_["midi"] = "audio/midi";
    mime_["mime"] = "message/rfc822";
    mime_["mml"] = "application/mathml+xml";
    mime_["mng"] = "video/x-mng";
    mime_["mov"] = "video/quicktime";
    mime_["mp3"] = "audio/mpeg";
    mime_["mp4"] = "video/mp4";
    mime_["mp4v"] = "video/mp4";
    mime_["mpeg"] = "video/mpeg";
    mime_["mpg"] = "video/mpeg";
    mime_["ms"] = "text/troff";
    mime_["msi"] = "application/x-msdownload";
    mime_["odp"] = "application/vnd.oasis.opendocument.presentation";
    mime_["ods"] = "application/vnd.oasis.opendocument.spreadsheet";
    mime_["odt"] = "application/vnd.oasis.opendocument.text";
    mime_["ogg"] = "application/ogg";
    mime_["p"] = "text/x-pascal";
    mime_["pas"] = "text/x-pascal";
    mime_["pbm"] = "image/x-portable-bitmap";
    mime_["pdf"] = "application/pdf";
    mime_["pem"] = "application/x-x509-ca-cert";
    mime_["pgm"] = "image/x-portable-graymap";
    mime_["pgp"] = "application/pgp-encrypted";
    mime_["pkg"] = "application/octet-stream";
    mime_["pl"] = "text/x-script.perl";
    mime_["pm"] = "text/x-script.perl-module";
    mime_["png"] = "image/png";
    mime_["pnm"] = "image/x-portable-anymap";
    mime_["ppm"] = "image/x-portable-pixmap";
    mime_["pps"] = "application/vnd.ms-powerpoint";
    mime_["ppt"] = "application/vnd.ms-powerpoint";
    mime_["ps"] = "application/postscript";
    mime_["psd"] = "image/vnd.adobe.photoshop";
    mime_["py"] = "text/x-script.python";
    mime_["qt"] = "video/quicktime";
    mime_["ra"] = "audio/x-pn-realaudio";
    mime_["rake"] = "text/x-script.ruby";
    mime_["ram"] = "audio/x-pn-realaudio";
    mime_["rar"] = "application/x-rar-compressed";
    mime_["rb"] = "text/x-script.ruby";
    mime_["rdf"] = "application/rdf+xml";
    mime_["roff"] = "text/troff";
    mime_["rpm"] = "application/x-redhat-package-manager";
    mime_["rss"] = "application/rss+xml";
    mime_["rtf"] = "application/rtf";
    mime_["ru"] = "text/x-script.ruby";
    mime_["s"] = "text/x-asm";
    mime_["sgm"] = "text/sgml";
    mime_["sgml"] = "text/sgml";
    mime_["sh"] = "application/x-sh";
    mime_["sig"] = "application/pgp-signature";
    mime_["snd"] = "audio/basic";
    mime_["so"] = "application/octet-stream";
    mime_["svg"] = "image/svg+xml";
    mime_["svgz"] = "image/svg+xml";
    mime_["swf"] = "application/x-shockwave-flash";
    mime_["t"] = "text/troff";
    mime_["tar"] = "application/x-tar";
    mime_["tbz"] = "application/x-bzip-compressed-tar";
    mime_["tci"] = "application/x-topcloud";
    mime_["tcl"] = "application/x-tcl";
    mime_["tex"] = "application/x-tex";
    mime_["texi"] = "application/x-texinfo";
    mime_["texinfo"] = "application/x-texinfo";
    mime_["text"] = "text/plain";
    mime_["tif"] = "image/tiff";
    mime_["tiff"] = "image/tiff";
    mime_["torrent"] = "application/x-bittorrent";
    mime_["tr"] = "text/troff";
    mime_["ttf"] = "application/x-font-ttf";
    mime_["txt"] = "text/plain";
    mime_["vcf"] = "text/x-vcard";
    mime_["vcs"] = "text/x-vcalendar";
    mime_["vrml"] = "model/vrml";
    mime_["war"] = "application/java-archive";
    mime_["wav"] = "audio/x-wav";
    mime_["webm"] = "video/webm";
    mime_["wma"] = "audio/x-ms-wma";
    mime_["wmv"] = "video/x-ms-wmv";
    mime_["wmx"] = "video/x-ms-wmx";
    mime_["woff"] = "application/x-font-woff";
    mime_["wrl"] = "model/vrml";
    mime_["wsdl"] = "application/wsdl+xml";
    mime_["xbm"] = "image/x-xbitmap";
    mime_["xhtml"] = "application/xhtml+xml";
    mime_["xls"] = "application/vnd.ms-excel";
    mime_["xlsx"] = "application/x-msdownload";
    mime_["xml"] = "application/xml";
    mime_["xpm"] = "image/x-xpixmap";
    mime_["xsl"] = "application/xml";
    mime_["xslt"] = "application/xslt+xml";
    mime_["yaml"] = "text/yaml";
    mime_["yml"] = "text/yaml";
    mime_["zip"] = "application/zip";
}

} // impl

std::shared_ptr<server> server::create(boost::asio::io_service& ios, boost::program_options::variables_map& vm)
{
    std::shared_ptr<server> ptr(new impl::server(ios, vm));
    return ptr;
}

} // p2p
} // c2c
