#include <QGuiApplication>
#include <QQmlApplicationEngine>

#include "qc2c.h"

#include <QQmlEngine>
#include <QQmlContext>

#include "srv.h"

int main(int argc, char *argv[])
{
    QCoreApplication::setAttribute(Qt::AA_EnableHighDpiScaling);

    QGuiApplication app(argc, argv);
    c2c::srv::instance().start(argc, argv);

    qmlRegisterUncreatableType<qc2c>("tunneleffect.C2C", 1, 0, "C2C", "c2c can't be instantiated directly");
    qmlRegisterUncreatableType<qdb>("tunneleffect.DB", 1, 0, "DB", "db can't be instantiated directly");

    QQmlApplicationEngine engine;
    engine.rootContext()->setContextProperty("c2c", qc2c::instance());

    engine.load(QUrl(QStringLiteral("qrc:/main.qml")));
    if (engine.rootObjects().isEmpty())
    {
        c2c::srv::instance().stop();
        return -1;
    }

    int rc = app.exec();
    c2c::srv::instance().stop();
    return rc;
}
