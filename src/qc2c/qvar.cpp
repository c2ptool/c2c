#include "qvar.h"

namespace c2c {

void qvar2var(const QVariant& src, c2c::var_t& dst)
{
    switch(src.type())
    {
    case QVariant::Type::Bool: dst = src.toBool(); break;
    case QVariant::Type::Int: dst = src.toInt(); break;
    case QVariant::Type::UInt: dst = src.toUInt(); break;
    case QVariant::Type::LongLong: dst = int64_t(src.toLongLong()); break;
    case QVariant::Type::ULongLong: dst = uint64_t(src.toULongLong()); break;
    case QVariant::Type::Double: dst = src.toDouble(); break;
    case QVariant::Type::String: dst = src.toString().toStdString(); break;
    case QVariant::Type::ByteArray:
        {
            QByteArray ba = src.toByteArray();
            dst = c2c::binary_t(ba.begin(), ba.end());
        }
        break;
    case QVariant::Type::List:
        {
            c2c::vec_t v(new std::vector<c2c::item_t>());
            qlist2vec(src.toList(), v);
            dst = v;
        }
        break;
    case QVariant::Type::Map:
    default:
        {
            c2c::map_t m(new std::map<std::string, c2c::item_t>());
            qmap2map(src.toMap(), m);
            dst = m;
        }
        break;
    }
}

void qmap2map(const QMap<QString, QVariant>& src, c2c::map_t& dst)
{
    std::map<std::string, c2c::item_t>& d = *dst;
    for(auto n=src.begin(); n!=src.end(); n++)
    {
        c2c::item_t& v = d[n.key().toStdString()];
        qvar2var(n.value(), v.value);
    }
}

void qlist2vec(const QList<QVariant>& src, c2c::vec_t& dst)
{
    std::vector<c2c::item_t>& v = *dst;
    for(auto n=src.begin(); n<src.end(); n++)
    {
        v.resize(v.size()+1);
        qvar2var(*n, v.back().value);
    }
}

void var2qvar(const c2c::var_t& src, QVariant& dst)
{
    struct visitor
    {
        QVariant& qvar;
        visitor(QVariant& qv) : qvar(qv) {}
        bool operator()(nil_t) const { return true; }
        bool operator()(bool v) const { qvar = QVariant(v); return true; }
        bool operator()(int8_t v) const { qvar = QVariant(v); return true; }
        bool operator()(uint8_t v) const { qvar = QVariant(v); return true; }
        bool operator()(int16_t v) const { qvar = QVariant(v); return true; }
        bool operator()(uint16_t v) const { qvar = QVariant(v); return true; }
        bool operator()(int32_t v) const { qvar = QVariant(v); return true; }
        bool operator()(uint32_t v) const { qvar = QVariant(v); return true; }
        bool operator()(int64_t v) const { qvar = QVariant(qlonglong(v)); return true; }
        bool operator()(uint64_t v) const { qvar = QVariant(qulonglong(v)); return true; }
        bool operator()(float v) const { qvar = QVariant(v); return true;  }
        bool operator()(double v) const { qvar = QVariant(v); return true; }
        bool operator()(const std::string& v) const {  qvar = QVariant(v.c_str()); return true; }
        bool operator()(const binary_t& v) const { qvar = QVariant(QByteArray((const char *)v.data(), int(v.size()))); return true; }
        bool operator()(const map_t& v) const {
            QVariantMap m;
            for(auto n=v->cbegin(); n!=v->cend(); n++)
            {

                visitor c(m[n->first.c_str()]);
                mpark::visit(c, n->second.value);
            }
            qvar = QVariant(m);
            return true;
        }
        bool operator()(const vec_t& v) const {
            QVariantList l;
            for(auto n=v->cbegin(); n<v->cend(); n++)
            {

                QVariant q; visitor c(q);
                mpark::visit(c, n->value);
                l.push_back(q);
            }
            qvar = QVariant(l);
            return true;
        }
    };

    visitor c(dst);
    mpark::visit(c, src);
}

}
