#ifndef HASH_H
#define HASH_H

#include <QApplication>
#include <QWidget>
#include <QPushButton>
#include <QDialog>
#include <QString>
#include <QLabel>
#include <QFileDialog>
#include <QLineEdit>
#include <QGridLayout>
#include <QRegExp>
#include <QMessageBox>

#include "mysha.h"

class Hash : public QDialog
{
    Q_OBJECT

public:
    Hash();
    Hash(int);

private:
    int rep;

    QLabel *labelPlain;
    QLabel *labelHash;

    QPushButton *buttonCancel;
    QPushButton *buttonBrowse;
    QPushButton *buttonHash;

    QLineEdit *lePlain;
    QLineEdit *leHash;

    QFileDialog *fdPlain;

    QRegExp *reFileName;

    QMessageBox *mb;

    QGridLayout *gl;

    MySha *mySha;

public slots:
    void hashSHA256();
    void hashSHA512();
    void hashSHA1();

};
#endif // HASH_H
