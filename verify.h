#ifndef VERIFY_H
#define VERIFY_H

#include <QPushButton>
#include <QLabel>
#include <QFileDialog>
#include <QLineEdit>
#include <QGridLayout>
#include <QMessageBox>
#include <QDialog>

#include "rsa.h"
#include "elgamal.h"
#include "dsa.h"

class Verify : public QDialog
{
    Q_OBJECT
public:
    Verify();
    Verify(int);

private:
    int rep;

    QPushButton *buttonBrowseHash;
    QPushButton *buttonBrowseSigned;
    QPushButton *buttonBrowsePuKey;
    QPushButton *buttonCancel;
    QPushButton *buttonCompute;

    QLabel *labelHash;
    QLabel *labelSigned;
    QLabel *labelPuKey;

    QFileDialog *fdHash;
    QFileDialog *fdSigned;
    QFileDialog *fdPuKey;

    QLineEdit *leHash;
    QLineEdit *leSigned;
    QLineEdit *lePuKey;

    QMessageBox *mb;

    QRegExp *rePuKey;
    QRegExp *reSign;
    QRegExp *reHash;

    QGridLayout *gl;

    ElGamal *elGamal;
    RSA *rsa;
    DSA *dsa;

signals:

public slots:
    void computeRSA();
    void computeElGamal();
    void computeDSA();
};

#endif // VERIFY_H
