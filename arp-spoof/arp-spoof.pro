QT -= gui

CONFIG += c++11 console
CONFIG -= app_bundle
LIBS += -lpcap

DEFINES += QT_DEPRECATED_WARNINGS

SOURCES += \
        arphdr.cpp \
        ethhdr.cpp \
        ip.cpp \
        mac.cpp \
        main.cpp

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

HEADERS += \
    arphdr.h \
    ethhdr.h \
    ip.h \
    mac.h \
    mylibnet.h
