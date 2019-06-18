#include <QGuiApplication>
#include <QQmlApplicationEngine>

#include <QDir>

#include "qc2c.h"

#include <QQmlEngine>
#include <QQmlContext>

#include "srv.h"

int main(int argc, char *argv[])
{
    QDir currentDir;
    QCoreApplication::setAttribute(Qt::AA_EnableHighDpiScaling);

    QGuiApplication app(argc, argv);
    c2c::srv::instance().start(argc, argv);

    qmlRegisterUncreatableType<qc2c>("tunelleffect", 1, 0, "tunelleffect", "c2c can't be instantiated directly");
    qmlRegisterUncreatableType<qdb>("tunelleffect.db", 1, 0, "tunelleffect.db", "db can't be instantiated directly");

    QQmlApplicationEngine engine;
    engine.rootContext()->setContextProperty("c2c", qc2c::instance());

    engine.load(QUrl(QStringLiteral("file:///")+currentDir.absolutePath()+"/main.qml"));

    if (engine.rootObjects().isEmpty())
        return -1;

    return app.exec();
}
