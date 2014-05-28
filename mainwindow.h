#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QApplication>
#include <QWidget>
#include <QPushButton>
#include <QComboBox>
#include <QLabel>
#include <QString>
#include <QStringList>
#include <QGridLayout>
#include <QTextEdit>

#include "decipher.h"
#include "cipher.h"
#include "sign.h"
#include "generatekey.h"
#include "hash.h"
#include "verify.h"

class MainWindow : public QWidget
{
    Q_OBJECT
    
public:
    MainWindow();
    int getHashSelected() const {return comboHash->currentIndex();}
    int getCipherSelected() const {return comboCipher->currentIndex();}
    int getDecipherSelected() const {return comboDecipher->currentIndex();}
    int getSignSelected() const {return comboSign->currentIndex();}
    int getGenerateKeySelected() const {return comboGenerateKey->currentIndex();}
    int getVerifySelected() const {return comboVerify->currentIndex();}

public slots:
    void openHash();
    void openGenerateKey();
    void openCipher();
    void openDecipher();
    void openSign();
    void openVerify();
    void viewFile1(QString);
    void viewFile2(QString);

signals:
    void hashSelected(int);
    void generateKeySelected(int);
    void cipherSelected(int);   
    void decipherSelected(int);
    void signSelected(int);
    void verifSelected(int);
    
private:
    char c;

    QMessageBox *mbInformation;

    QPushButton *buttonHash;
    QPushButton *buttonGenerateKey;
    QPushButton *buttonCipher;
    QPushButton *buttonDecipher;
    QPushButton *buttonSign;
    QPushButton *buttonVerify;
    QPushButton *buttonQuit;
    QPushButton *buttonBrowseFile1;
    QPushButton *buttonBrowseFile2;

    QFileDialog *fdFile1;
    QFileDialog *fdFile2;

    QComboBox *comboHash;
    QComboBox *comboGenerateKey;
    QComboBox *comboCipher;
    QComboBox *comboDecipher;
    QComboBox *comboSign;
    QComboBox *comboVerify;

    QLabel *labelAfficherFichier1;
    QLabel *labelAfficherFichier2;
    QLabel *labelHash;
    QLabel *labelGenerateKey;
    QLabel *labelCipher;
    QLabel *labelDecipher;
    QLabel *labelSign;
    QLabel *labelVerify;

    QTextEdit *qtFichier1;
    QTextEdit *qtFichier2;

    QGridLayout *glMain;
    QGridLayout *glTextEdit;
    QGridLayout *gl;
    QGridLayout *glHash;
    QGridLayout *glGenKey;
    QGridLayout *glCipher;
    QGridLayout *glDecipher;
    QGridLayout *glSign;
    QGridLayout *glVerify;

    Cipher *cipher;
    Decipher *decipher;
    Sign *sign;
    Verify *verify;
    GenerateKey *generateKey;
    Hash *hash;
};

#endif // MainWindow_H
