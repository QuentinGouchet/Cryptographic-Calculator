#ifndef DECIPHER_H
#define DECIPHER_H

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
#include "elgamal.h"
#include "rsa.h"

class Decipher : public QDialog
{
    Q_OBJECT

public:
    Decipher();
    Decipher(int);

private:
    unsigned int rep;
    QPushButton *buttonBrowseCipher;
    QPushButton *buttonBrowsePrivateKey;
    QPushButton *buttonCancel;
    QPushButton *buttonCompute;

    QLabel *labelPlain;
    QLabel *labelCipher;
    QLabel *labelPrivateKey;

    QFileDialog *fdCipher;
    QFileDialog *fdPrivateKey;

    QLineEdit *lePlain;
    QLineEdit *leCipher;
    QLineEdit *lePrivatekey;

    QMessageBox *mb;

    QRegExp *rePlain;
    QRegExp *rePrKey;
    QRegExp *reCipher;

    ElGamal *elGamal;
    Rabin *rabin;
    RSA *rsa;

    QGridLayout *gl;

public slots:
    void computeRSA();
    void computeRSACRT();
    void computeRSAOAEP();
    void computeElGamal();
    void computeRabin();

signals:
    void clickedCompute();
};
#endif // DECIPHER_H
