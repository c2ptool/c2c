#ifndef L_QC2C_H
#define L_QC2C_H

#include <QObject>
#include "var.h"

class qdb : public QObject
{
    Q_OBJECT

    std::string name_;
    c2c::vec_t pfx_;
    qlonglong request_id_;

    explicit qdb(QObject *parent = nullptr);
    void __pfx_add(c2c::vec_t& base, const QVariantList& pfx);

public:
    qdb(const QString& name, QObject *parent = nullptr);
    qdb(const QString& name, const QVariantList& pfx, QObject *parent = nullptr);

    Q_INVOKABLE qdb* at(const QVariantList& pfx);
    Q_INVOKABLE void put(const QVariantList& pfx, const QVariant& val);
    Q_INVOKABLE void del(const QVariantList& pfx);
    Q_INVOKABLE qlonglong get(const QVariantList& pfx, qlonglong id = -1);
    Q_INVOKABLE void call(const QVariantList& pfx, const QVariantList& pars);
    Q_INVOKABLE qlonglong call_r(const QVariantList& pfx, const QVariantList& pars, qlonglong id = -1);

signals:
    void reply(qlonglong id, const QString& method, const QVariant& value);
};

class qc2c : public QObject
{
    Q_OBJECT

    explicit qc2c(QObject *parent = nullptr);
    static qc2c *instance_;

public:
    Q_INVOKABLE qdb* open(const QString& name);

    static qc2c *instance();
};

#endif
