#include "mainwindow.h"

MainWindow::MainWindow() : QWidget()
{
    setFixedSize(1200, 600);
    this->setWindowTitle("Cryptographic Calculator");

    QStringList listHash(QStringList() << "SHA-256" << "SHA-512" << "SHA1");
    QStringList listGenerateKey(QStringList() << "RSA" << "EL GAMAL" << "RABIN" << "DSA");
    QStringList listCipher(QStringList() << "RSA" << "EL GAMAL" << "RABIN" << "RSA-OAEP");
    QStringList listDecipher(QStringList() << "RSA" << "RSA-CRT" << "EL GAMAL" << "RABIN" << "RSA-OAEP");
    QStringList listSign(QStringList() << "RSA" << "EL GAMAL" << "DSA");
    QStringList listVerify(QStringList() << "RSA" << "EL GAMAL" << "DSA");
    QStringList listFilter(QStringList() << "*.puKey" << "*.prKey" << "*.plain" << "*.cipher");

    labelHash = new QLabel("Hash file :",this);
    labelGenerateKey = new QLabel("Generate keys :");
    labelCipher = new QLabel("Cipher :",this);
    labelDecipher = new QLabel("Decipher :",this);
    labelSign = new QLabel("Sign :",this);
    labelVerify = new QLabel("Verify :", this);

    buttonHash = new QPushButton("Hash file!", this);
    buttonGenerateKey = new QPushButton("Generate keys!", this);
    buttonCipher = new QPushButton("Cipher it!", this);
    buttonDecipher = new QPushButton("Decipher it!", this);
    buttonSign = new QPushButton("Sign it!", this);
    buttonVerify = new QPushButton("Verify it !", this);
    buttonQuit = new QPushButton("Quit", this);
    buttonBrowseFile1 = new QPushButton("B\nr\no\nw\ns\ne", this);
    buttonBrowseFile2 = new QPushButton("B\nr\no\nw\ns\ne", this);

    fdFile1 = new QFileDialog(this);
    fdFile1->setDirectory("../ressources/");
    fdFile1->setNameFilters(listFilter);
    fdFile2 = new QFileDialog(this);
    fdFile2->setDirectory("../ressources/");
    fdFile2->setNameFilters(listFilter);

    comboHash = new QComboBox(this);
    comboGenerateKey = new QComboBox(this);
    comboCipher = new QComboBox(this);
    comboDecipher = new QComboBox(this);
    comboSign = new QComboBox(this);
    comboVerify = new QComboBox(this);

    qtFichier1 = new QTextEdit(this);
    qtFichier1->setReadOnly(true);
    qtFichier2 = new QTextEdit(this);
    qtFichier2->setReadOnly(true);

    comboHash->addItems(listHash);
    comboGenerateKey->addItems(listGenerateKey);
    comboCipher->addItems(listCipher);
    comboDecipher->addItems(listDecipher);
    comboSign->addItems(listSign);
    comboVerify->addItems(listVerify);

    glMain = new QGridLayout(this);
    glTextEdit = new QGridLayout();
    gl = new QGridLayout();
    glHash = new QGridLayout();
    glGenKey = new QGridLayout();
    glCipher = new QGridLayout();
    glDecipher = new QGridLayout();
    glSign = new QGridLayout();
    glVerify = new QGridLayout();

    glHash->addWidget(labelHash, 0, 0);
    glHash->addWidget(comboHash, 0, 1);

    glGenKey->addWidget(labelGenerateKey, 0, 0);
    glGenKey->addWidget(comboGenerateKey, 0, 1);

    glCipher->addWidget(labelCipher, 0, 0);
    glCipher->addWidget(comboCipher, 0, 1);

    glDecipher->addWidget(labelDecipher, 0, 0);
    glDecipher->addWidget(comboDecipher, 0, 1);

    glSign->addWidget(labelSign, 0, 0);
    glSign->addWidget(comboSign, 0, 1);

    glVerify->addWidget(labelVerify, 0, 0);
    glVerify->addWidget(comboVerify, 0, 1);

    gl->addLayout(glHash, 1, 0);
    gl->addWidget(buttonHash, 1, 1);

    gl->addLayout(glGenKey, 2, 0);
    gl->addWidget(buttonGenerateKey, 2, 1);

    gl->addLayout(glCipher, 3, 0);
    gl->addWidget(buttonCipher, 3, 1);

    gl->addLayout(glDecipher, 4, 0);
    gl->addWidget(buttonDecipher, 4, 1);

    gl->addLayout(glSign, 5, 0);
    gl->addWidget(buttonSign, 5, 1);

    gl->addLayout(glVerify, 6, 0);
    gl->addWidget(buttonVerify, 6, 1);

    gl->setMargin(25);
    gl->setSpacing(25);

    glTextEdit->addWidget(qtFichier1, 0, 1);
    glTextEdit->addWidget(qtFichier2, 1, 1);

    glTextEdit->addWidget(buttonBrowseFile1, 0, 0);
    glTextEdit->addWidget(buttonBrowseFile2, 1, 0);

    glMain->addLayout(gl, 0, 0);
    glMain->addLayout(glTextEdit, 0, 1);
    glMain->addWidget(buttonQuit, 1, 1);

    buttonBrowseFile1->setFixedHeight(270);
    buttonBrowseFile1->setFixedWidth(50);
    buttonBrowseFile2->setFixedHeight(270);
    buttonBrowseFile2->setFixedWidth(50);

    QObject::connect(buttonHash,SIGNAL(clicked()),this,SLOT(openHash()));
    QObject::connect(buttonGenerateKey,SIGNAL(clicked()),this,SLOT(openGenerateKey()));
    QObject::connect(buttonCipher,SIGNAL(clicked()),this,SLOT(openCipher()));
    QObject::connect(buttonDecipher,SIGNAL(clicked()),this,SLOT(openDecipher()));
    QObject::connect(buttonQuit,SIGNAL(clicked()),this,SLOT(close()));
    QObject::connect(buttonSign, SIGNAL(clicked()), this, SLOT(openSign()));
    QObject::connect(buttonVerify, SIGNAL(clicked()), this, SLOT(openVerify()));
    QObject::connect(buttonBrowseFile1, SIGNAL(clicked()), fdFile1, SLOT(exec()));
    QObject::connect(buttonBrowseFile2, SIGNAL(clicked()), fdFile2, SLOT(exec()));
    QObject::connect(fdFile1, SIGNAL(fileSelected(QString)), qtFichier1, SLOT(clear()));
    QObject::connect(fdFile1, SIGNAL(fileSelected(QString)), this, SLOT(viewFile1(QString)));
    QObject::connect(fdFile2, SIGNAL(fileSelected(QString)), qtFichier2, SLOT(clear()));
    QObject::connect(fdFile2, SIGNAL(fileSelected(QString)), this, SLOT(viewFile2(QString)));

    this->setLayout(glMain);
}

void MainWindow::openHash()
{
    hash = new Hash(this->getHashSelected());
    emit hashSelected(this->getHashSelected());
    hash->exec();
}

void MainWindow::openGenerateKey()
{
    generateKey = new GenerateKey(this->getGenerateKeySelected());
    emit generateKeySelected(this->getGenerateKeySelected());
    generateKey->exec();
}

void MainWindow::openCipher()
{
    cipher = new Cipher(this->getCipherSelected());
    emit cipherSelected(this->getCipherSelected());
    cipher->exec();
}

void MainWindow::openDecipher()
{
    decipher = new Decipher(this->getDecipherSelected());
    emit decipherSelected(this->getDecipherSelected());
    decipher->exec();
}

void MainWindow::openSign()
{
    sign = new Sign(this->getSignSelected());
    emit signSelected(this->getSignSelected());
    sign->exec();
}

void MainWindow::openVerify(){
    verify = new Verify(this->getVerifySelected());
    emit verifSelected(this->getVerifySelected());
    verify->exec();
}

void MainWindow::viewFile1(QString fileToView){
    QString aString;
    FILE *file;
    if((file = fopen(fileToView.toLocal8Bit().constData(), "r")) == NULL){
        mbInformation = new QMessageBox(this);
        mbInformation->setText("Cannot open the selected file");
        mbInformation->exec();
    }
    else{
        while((c = fgetc(file)) != EOF){
            aString.append(c);
        }
    }
    fclose(file);
    qtFichier1->append(aString);
}

void MainWindow::viewFile2(QString fileToView){
    QString aString;
    FILE *file;
    if((file = fopen(fileToView.toLocal8Bit().constData(), "r")) == NULL){
        mbInformation = new QMessageBox(this);
        mbInformation->setText("Cannot open the selected file");
        mbInformation->exec();
    }
    else{
        while((c = fgetc(file)) != EOF){
            aString.append(c);
        }
    }
    fclose(file);
    qtFichier2->append(aString);
}
