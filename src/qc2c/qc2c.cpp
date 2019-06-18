#include "qc2c.h"
#include "srv.h"
#include "qvar.h"
#include "func.h"

#include <iostream>

qc2c* qc2c::instance_ = nullptr;

qc2c::qc2c(QObject *parent) : QObject(parent)
{
}

Q_INVOKABLE qdb *qc2c::open(const QString& name) {
    return new qdb(name, this);
}

qc2c *qc2c::instance()
{
    if(!instance_)
        instance_ = new qc2c;
    return instance_;
}

qdb::qdb(QObject *parent) : QObject(parent), pfx_(new std::vector<c2c::item_t>()), request_id_(0)
{
}

qdb::qdb(const QString& name, QObject *parent) : QObject(parent), name_(name.toStdString()), pfx_(new std::vector<c2c::item_t>()), request_id_(0)
{
}

qdb::qdb(const QString& name, const QVariantList& pfx, QObject *parent) : QObject(parent), name_(name.toStdString()), pfx_(new std::vector<c2c::item_t>()), request_id_(0)
{
    __pfx_add(pfx_, pfx);
}

void qdb::__pfx_add(c2c::vec_t& base, const QVariantList& pfx)
{
    for(QVariantList::const_iterator it=pfx.begin(); it!=pfx.end(); it++)
    {
        base->resize(base->size()+1);
        c2c::qvar2var(*it, base->back().value);
    }
}

Q_INVOKABLE qdb *qdb::at(const QVariantList& pfx) {
    return new qdb(name_.c_str(), pfx, this);
}

Q_INVOKABLE void qdb::put(const QVariantList& pfx, const QVariant& val)
{
    c2c::vec_t base(new std::vector<c2c::item_t>());
    for(auto n=pfx_->begin(); n<pfx_->end(); n++)
        base->push_back({*n});
    __pfx_add(base, pfx);
    c2c::var_t v;
    c2c::qvar2var(val, v);
    c2c::srv::instance().put(name_, base, v);
}

Q_INVOKABLE void qdb::del(const QVariantList& pfx)
{
    c2c::vec_t base(new std::vector<c2c::item_t>());
    for(auto n=pfx_->begin(); n<pfx_->end(); n++)
        base->push_back({*n});
    __pfx_add(base, pfx);
    c2c::srv::instance().del(name_, base);
}

Q_INVOKABLE qlonglong qdb::get(const QVariantList& pfx, qlonglong id)
{
    if(id < 0)
        id = request_id_++;
    c2c::vec_t base(new std::vector<c2c::item_t>());
    for(auto n=pfx_->begin(); n<pfx_->end(); n++)
        base->push_back({*n});
    __pfx_add(base, pfx);
    c2c::call_t rep = std::bind([this](qlonglong id, c2c::connection_ptr con, const std::string& meth, c2c::var_t val) -> bool {
        QVariant qval;
        c2c::var2qvar(val, qval);
        emit reply(id, meth.c_str(), qval);
    }, id, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3);
    c2c::srv::instance().get(name_, base, rep);
    return id;
}

Q_INVOKABLE void qdb::call(const QVariantList& pfx, const QVariantList& args)
{
    c2c::vec_t key(new std::vector<c2c::item_t>());
    for(auto n=pfx_->begin(); n<pfx_->end(); n++)
         key->push_back({*n});
    __pfx_add(key, pfx);
    c2c::vec_t pars(new std::vector<c2c::item_t>());
    c2c::qlist2vec(args, pars);
    c2c::srv::instance().call(name_, key, pars);
}

Q_INVOKABLE qlonglong qdb::call_r(const QVariantList& pfx, const QVariantList& args, qlonglong id)
{
    if(id < 0)
        id = request_id_++;
    c2c::vec_t key(new std::vector<c2c::item_t>());
    for(auto n=pfx_->begin(); n<pfx_->end(); n++)
         key->push_back({*n});
    __pfx_add(key, pfx);
    c2c::vec_t pars(new std::vector<c2c::item_t>());
    c2c::qlist2vec(args, pars);
    c2c::call_t rep = std::bind([this](qlonglong id, c2c::connection_ptr con, const std::string& meth, c2c::var_t val) -> bool {
        QVariant qval;
        c2c::var2qvar(val, qval);
        emit reply(id, meth.c_str(), qval);
            return true;
    }, id, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3);
    c2c::srv::instance().call_r(name_, key, pars, rep);
    return id;
}
