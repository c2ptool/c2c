#ifndef L_RESPONSE_H
#define L_RESPONSE_H

#include "work.h"

namespace c2c {
    namespace lua {

    struct response : public  std::enable_shared_from_this<response>
    {
        std::weak_ptr<worker::server> w_;
        call_t r_;

        response(const std::shared_ptr<worker::server>& w, call_t r);
        void reply(sol::variadic_args args);
        static bool reg(sol::state_view& lua);
    };

}}

#endif
