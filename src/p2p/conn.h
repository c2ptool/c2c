#ifndef L_CONN_H
#define L_CONN_H

#include "var.h"
#include <websocketpp/common/connection_hdl.hpp>

namespace c2c {

typedef enum {
    CON_UNKNOWN=0,
    CON_MSGPACK,
    CON_JSON
} CON_TYPE;

typedef enum {
    CON_SERVER_1=0,
    CON_SERVER_2,
    CON_SERVER_3,
    CON_SERVER_4,
    CON_SERVER_5,
    CON_SERVER_6,
    CON_SERVER_7,
    CON_SERVER_8,
    CON_SERVER_9,
    CON_SERVER_10,
    CON_SERVER_MAX,
    CON_SERVER=128,
    CON_CLIENT=129
} CON_SRC;

struct connection_t
{
    websocketpp::connection_hdl hdl;
    CON_SRC con;
    CON_TYPE type;
    std::string uri;
    std::vector<std::string> proto;
    std::string ca;
    binary_t x509_digest;
    binary_t id;
};

typedef std::shared_ptr<connection_t> connection_ptr;

}

#endif
