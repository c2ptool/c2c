import QtQuick 2.9
import QtQuick.Controls 2.2
import lykhny 1.0

Page {
    width: 600
    height: 400

    title: qsTr("Page 1")

    Lykhny {
        id: lhny
    }

    db: lhny.open("db1")

    Label {
        text: qsTr("You are on Page 1.")
        anchors.centerIn: parent
    }
}
