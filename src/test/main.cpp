void f_on_t(int i, const std::string& s)
{
    std::cout << "msgpack_on!\n";
}

        call_t f_c = [](connection_ptr con, const std::string& method, const std::string& params) -> bool
        {
            std::string json;

            if(!conv::msgpack_to_json(params, json))
                std::cout << "error convert params to json\n";
            else
                std::cout << "method:" << method << "\n" << json << "\n";

            return true;
        };

        call_r_t f_cr = [](connection_ptr con, const std::string& method, const std::string& params, reply_t r) -> bool
        {
            std::string json, rc;
            if(!conv::msgpack_to_json(params, json))
                std::cout << "error convert params to json\n";
            else
                std::cout << "method:" << method << "\n" << json << "\n";

            //f_on p;
            //std::function<decltype(f_on::on)> f = std::bind(&f_on::on, &p, std::placeholders::_1, std::placeholders::_2);

            conv::json_to_msgpack("{\"state\":\"OK\"}", rc);

            /*msgpack_writer_t wr(rc);
            msgpack::packer<msgpack_writer_t> pk(wr);
            pk.pack_map(3);
            pk.pack("state");
            pk.pack_str(2);
            pk.pack_str_body("OK", 2);
            const uint8_t bin[] = {1,2,3,4,251};
            pk.pack("a");
            pk.pack_bin(5);
            pk.pack_bin_body((const char *)bin, 5);
            pk.pack("b");
            pk.pack_ext(5,0);
            pk.pack_ext_body((const char *)bin, 5);*/
            r("result", rc);

            return true;
        };

        //uint64_t next_con_id = 0;
        //std::map<uint64_t, connection_ptr> cons;

        on_connection_t f_open = [&](connection_ptr)
        {
            std::cout << "connection is opened\n";
        };

        on_connection_t f_close = [&](connection_ptr)
        {
            std::cout << "connection is closed\n";
        };

        std::shared_ptr<net::server> s =  std::make_shared<net::server>(ios, vm);
        s->join("test", f_open, f_close, f_c, f_cr);
        s->start();

        struct F_ON
        {
            void f_on_0(connection_ptr)
            {
                std::cout << "f_on_0!\n";
            }
            void f_on_1(connection_ptr con, int i, std::string s)
            {
                std::cout << "f_on_1!\n";
            }
            void f_on_2(connection_ptr con, int i, std::string s, conv::respnse_t& r)
            {
                std::cout << "f_on_2!\n";
                r(1, "1111", std::string("2222"));
                r.error(1, "1111", std::string("2222"));
            }
            void f_on_3(connection_ptr con, conv::respnse_t& r)
            {
                std::cout << "f_on_3!\n";
                r(1, "1111", std::string("2222"));
            }
        };

        auto p = std::make_shared<F_ON>();

        auto f_0 = conv::bind(&F_ON::f_on_0, p, _1);
        auto f_1 = conv::bind(&F_ON::f_on_1, p, _1, _2, _3);
        auto f_2 = conv::bind(&F_ON::f_on_2, p, _1, _2, _3, _4);
        auto f_3 = conv::bind(&F_ON::f_on_3, p, _1, _2);

        connection_ptr c;
        conv::wrap(f_0)(c);

        std::string params;
        conv::msgpack_writer_t wr(params);
        msgpack::packer<conv::msgpack_writer_t> pk(wr);
        pk.pack_int(12);
        pk.pack_str(5);
        pk.pack_str_body("12345",5);

        conv::wrap(f_1)(c, params);

        reply_t rep = [&](const std::string& type, const std::string& data)
        {

        };

        conv::wrap_r(f_2)(c, params, rep);
        conv::wrap_r(f_3)(c, params, rep);

        std::string data;
        conv::to_msgpack m(data);
        m(1, "1111", std::string("2222"));
