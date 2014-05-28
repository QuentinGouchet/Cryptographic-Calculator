#ifndef SIGN_H
#define SIGN_H

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

#include "rsa.h"
#include "elgamal.h"
#include "dsa.h"

class Sign : public QDialog
{
    Q_OBJECT
public:
    Sign();
    Sign(int);

private:
    int rep;

    QPushButton *buttonBrowseHash;
    QPushButton *buttonBrowsePrKey;
    QPushButton *buttonBrowsePuKey;
    QPushButton *buttonCancel;
    QPushButton *buttonCompute;

    QLabel *labelHash;
    QLabel *labelPrKey;
    QLabel *labelPuKey;
    QLabel *labelFileNameSign;

    QFileDialog *fdHash;
    QFileDialog *fdPrKey;
    QFileDialog *fdPuKey;

    QLineEdit *leHash;
    QLineEdit *lePrKey;
    QLineEdit *lePuKey;
    QLineEdit *leFileNameSign;

    QRegExp *reFileName;
    QRegExp *rePrKey;
    QRegExp *reHash;
    QRegExp *rePuKey;

    QMessageBox *mb;

    ElGamal *elGamal;
    RSA *rsa;
    DSA *dsa;

    QGridLayout *gl;
    
signals:
    
public slots:
    void computeRSA();
    void computeElGamal();
    void computeDSA();
    
};

#endif // SIGN_H
