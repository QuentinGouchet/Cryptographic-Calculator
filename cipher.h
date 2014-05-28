#ifndef CIPHER_H
#define CIPHER_H

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

#include "rabin.h"
#include "rsa.h"
#include "elgamal.h"

class Cipher : public QDialog
{
    Q_OBJECT

public:
    Cipher();
    Cipher(int);

private:
    int rep;

    QPushButton *buttonBrowsePlain;
    QPushButton *buttonBrowsePublicKey;
    QPushButton *buttonCancel;
    QPushButton *buttonCompute;

    QLabel *labelPlain;
    QLabel *labelCipher;
    QLabel *labelPublicKey;

    QFileDialog *fdPlain;
    QFileDialog *fdPublicKey;

    QLineEdit *lePlain;
    QLineEdit *leCipher;
    QLineEdit *lePublicKey;

    QRegExp *rePlain;
    QRegExp *reCipher;
    QRegExp *rePuKey;

    QMessageBox *mb;

    QGridLayout *gl;

    RSA *rsa;
    ElGamal *elGamal;
    Rabin *rabin;

public slots:
    void computeRSA();
    void computeElGamal();
    void computeRabin();
    void computeRSAOAEP();
};
#endif // CIPHER_H
