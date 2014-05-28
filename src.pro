SOURCES += \
    cipher.cpp \
    sign.cpp \
    rabin.cpp \
    mainwindow.cpp \
    main.cpp \
    decipher.cpp \
    generatekey.cpp \
    hash.cpp \
    mysha.cpp \
    rsa.cpp \
    verify.cpp \
    elgamal.cpp \
    dsa.cpp \
    util.cpp

HEADERS += \
    sign.h \
    rabin.h \
    mainwindow.h \
    cipher.h \
    decipher.h \
    generatekey.h \
    hash.h \
    mysha.h \
    rsa.h \
    verify.h \
    elgamal.h \
    dsa.h \
    util.h

LIBS += -lgmp -lcrypto -Wall

QT += widgets
