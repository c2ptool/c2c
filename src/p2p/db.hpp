#ifndef L_DB_HPP
#define L_DB_HPP

#include "db.h"
#include <msgpack.hpp>

namespace c2c { namespace cxx {

    class db
    {
        db_layer<DB_DATA_LAYER> db_;

        struct stream
        {
            stream(std::string& data) : data_(data) {}
            void write(const char* buf, size_t len) { data_.append(buf, buf+len); }
        private:
            std::string& data_;
        };

        typedef msgpack::packer<stream> PK;

        class writer
        {
            std::string& data_;

            void write(PK& pk) {}

            template<typename T, typename... A>
            void write(PK& pk, const T& arg, const A&... args)
            {
                pk.pack(arg);
                write(pk, args...);
            }

        public:
            writer(std::string& data) : data_(data) {}

            template<typename... A>
            void operator ()(const A&... args)
            {
                stream fw(data_);
                PK pk(fw);
                write(pk, args...);
            }
        };

        std::string key_, val_;

    public:
        db(const c2c::db& a) { db_.attach(&a); }
        db(const db& a) { db_.attach(&a.db_); }
        db(const c2c::db& a, const std::string& pfx) { db_.attach(&a, pfx.data(), pfx.size()); }
        db(const db& a, const std::string& pfx) { db_.attach(&a.db_, pfx.data(), pfx.size()); }
        db(const c2c::db& a, const std::vector<char>& pfx) { db_.attach(&a, pfx.data(), pfx.size()); }
        db(const db& a, const std::vector<char>& pfx) { db_.attach(&a.db_, pfx.data(), pfx.size()); }
        db(const c2c::db& a, const std::vector<unsigned char>& pfx) { db_.attach(&a, (const char *)pfx.data(), pfx.size()); }
        db(const db& a, const std::vector<unsigned char>& pfx) { db_.attach(&a.db_, (const char *)pfx.data(), pfx.size()); }
        db(const std::string& path) { db_.open(path.c_str()); }
        db(const std::string& path, const std::string& pfx) { db_.open(path.c_str(), pfx.data(), pfx.size()); }
        db(const std::string& path, const std::vector<char>& pfx) { db_.open(path.c_str(), pfx.data(), pfx.size()); }
        db(const std::string& path, const std::vector<unsigned char>& pfx) { db_.open(path.c_str(), (const char *)pfx.data(), pfx.size()); }

        template<typename A>
        db operator [](const A& arg) const
        {
            std::string pfx; writer w(pfx); w(arg);
            return db(db_, pfx);
        }

        template<typename... A>
        db at(const A&... args) const
        {
            std::string pfx; writer w(pfx); w(args...);
            db r(db_, pfx);
            return r;
        }

        template<typename... A>
        void add_prefix(const A&... args)
        {
            std::string pfx; writer w(pfx); w(args...);
            db_.add_prefix(pfx.data(), pfx.size());
        }

        struct value_t
        {
            std::string data_;

            template<typename... A>
            value_t(const A&... a)
            {
                writer w(data_);
                w(a...);
            }
        };

        void __put(std::string& pfx, PK& pk, const value_t& val)
        {
            if(pfx.size()>0)
                db_.put(pfx.data(), pfx.size(), val.data_.data(), val.data_.size());
            else
                db_.put(val.data_.data(), val.data_.size());
        }

        template<typename V>
        void __put(std::string& pfx, PK& pk, const V& val)
        {
            std::string data; stream ss2(data); PK pk2(ss2); pk2.pack(val);
            if(pfx.size()>0)
                db_.put(pfx.data(), pfx.size(), data.data(), data.size());
            else
                db_.put(data.data(), data.size());
        }

        template<typename T, typename... A>
        void __put(std::string& pfx, PK& pk, const T& t, const A&... a)
        {
            pk.pack(t);
            __put(pfx, pk, a...);
        }

        template<typename... A>
        void put(const A&... a)
        {
            std::string pfx;
            stream ss(pfx);
            PK pk(ss);
            __put(pfx, pk, a...);
        }

        const std::string& get()
        {
            val_.clear();
            db_.get(val_);
            return val_;
        }

        template<typename... A>
        const std::string& get(const A&... args)
        {
            val_.clear();
            std::string pfx; writer w(pfx); w(args...);
            db_.get(pfx.data(), pfx.size(), val_);
            return val_;
        }

        inline bool del() { return db_.del(); }

        template<typename... A>
        bool del(const A&... args)
        {
            std::string pfx; writer w(pfx); w(args...);
            return db_.del(pfx.data(), pfx.size());
        }

        inline void begin() { db_.begin(); }
        inline void commit() { db_.commit(); }

        inline const std::string& key() { return key_; }
        inline const std::string& val() { return val_; }

        bool skip(int step = 1)
        {
            key_.clear(); val_.clear();
            return db_.skip(step, key_, val_);
        }

        bool seek()
        {
            key_.clear(); val_.clear();
            return db_.seek(key_, val_);
        }

        template<typename... A>
        bool seek(const A&... args)
        {
            key_.clear(); val_.clear();
            std::string pfx; writer w(pfx); w(args...);
            return db_.seek(pfx.data(), pfx.size(), key_, val_);
        }

        bool first()
        {
            key_.clear(); val_.clear();
            return db_.first(key_, val_);
        }

        bool last()
        {
            key_.clear(); val_.clear();
            return db_.last(key_, val_);
        }

        bool next()
        {
            key_.clear(); val_.clear();
            return db_.next(key_, val_);
        }

        bool prev()
        {
            key_.clear(); val_.clear();
            return db_.prev(key_, val_);
        }

        template<typename... A> class result_t;

        template<typename T> class result_t<T>
        {
            T& v_;
        public:
            result_t<T>(T& v) : v_(v) {}
            bool on(const std::string& data, size_t& off)
            {
                if(data.size() <= off)
                    return false;
                msgpack::object_handle oh = msgpack::unpack(data.data(), data.size(), off);
                msgpack::object obj = oh.get();
                obj.convert(v_);
                return true;
            }
            bool operator = (const std::string& data)
            {
                size_t off = 0; return on(data, off);
            }
        };

        template<typename T, typename... A> class result_t<T,  A...> : private result_t<A...>
        {
            T& v_;
        public:
            typedef result_t<A...> X;
            result_t<T, A...>(T& v, A&... a) : X(a...), v_(v) {}
            bool on(const std::string& data, size_t& off)
            {
                if(data.size() <= off)
                    return false;
                msgpack::object_handle oh = msgpack::unpack(data.data(), data.size(), off);
                msgpack::object obj = oh.get();
                obj.convert(v_);
                return X::on(data, off);
            }
            bool operator = (const std::string& data)
            {
                size_t off = 0; return on(data, off);
            }
        };
    };

    template<typename... A> inline db::result_t<A...> result(A&... a) { return db::result_t<A...>(a...); }
    template<typename... A> inline db::value_t value(const A&... a) { return db::value_t(a...); }

}}

#endif
