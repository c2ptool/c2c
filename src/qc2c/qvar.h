#ifndef Q_VAR_H
#define Q_VAR_H

#include <QVariant>
#include "var.h"

namespace c2c {

void qmap2map(const QMap<QString, QVariant>& src, c2c::map_t& dst);
void qlist2vec(const QList<QVariant>& src, c2c::vec_t& vec);
void qvar2var(const QVariant& src, c2c::var_t& dst);
void var2qvar(const c2c::var_t& src, QVariant& dst);

}

#endif
