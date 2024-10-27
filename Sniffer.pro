QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

CONFIG += c++11

# You can make your code fail to compile if it uses deprecated APIs.
# In order to do so, uncomment the following line.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

SOURCES += \
    capturethread.cpp \
    main.cpp \
    mainwindow.cpp \
    packageinfo.cpp

HEADERS += \
    capturethread.h \
    mainwindow.h \
    packageinfo.h

FORMS += \
    mainwindow.ui

INCLUDEPATH += D:\setting\winpcap\WpdPack_4_1_2\WpdPack\Include
LIBS += D:\setting\winpcap\WpdPack_4_1_2\WpdPack\Lib\x64\wpcap.lib
LIBS += D:\setting\winpcap\WpdPack_4_1_2\WpdPack\Lib\x64\Packet.lib
LIBS += -lws2_32

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

RESOURCES += \
    res.qrc
