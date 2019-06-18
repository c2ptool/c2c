import QtQuick 2.9
import QtQuick.Controls 2.2
import lykhny 1.0

Page {
    width: 600
    height: 400

    title: qsTr("Page 2")

    Lykhny {
        id: lhny
    }

    db: lhny.open("db2")

    Label {
        text: qsTr("You are on Page 2.")
        anchors.centerIn: parent
    }
}
