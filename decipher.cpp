#include "decipher.h"

Decipher::Decipher() : QDialog() {}

/*
    0 - RSA
    1 - RSA-CRT
    2 - EL GAMAL
    3 - RABIN
*/

Decipher::Decipher(int index): QDialog(){
    setFixedSize(800, 400);
    this->setWindowTitle("Decipher");

    labelCipher = new QLabel("Choose file to decipher :",this);
    labelPlain = new QLabel("Choose where to create output file :",this);
    labelPrivateKey = new QLabel("Choose which private key to use :",this);

    buttonBrowseCipher = new QPushButton("Browse", this);
    buttonBrowsePrivateKey = new QPushButton("Browse", this);
    buttonCancel = new QPushButton("Cancel", this);
    buttonCompute = new QPushButton("Compute", this);

    lePlain = new QLineEdit(this);
    leCipher = new QLineEdit(this);
    lePrivatekey = new QLineEdit(this);

    fdCipher = new QFileDialog(this);
    fdPrivateKey = new QFileDialog(this);

    fdCipher->setDirectory("../ressources/");
    fdPrivateKey->setDirectory("../ressources/");

    fdCipher->setNameFilter("*.cipher");
    fdPrivateKey->setNameFilter("*.prKey");

    gl = new QGridLayout(this);

    gl->addWidget(labelCipher, 0, 0);
    gl->addWidget(leCipher, 0, 1);
    gl->addWidget(buttonBrowseCipher, 0, 2);

    gl->addWidget(labelPrivateKey, 1, 0);
    gl->addWidget(lePrivatekey, 1, 1);
    gl->addWidget(buttonBrowsePrivateKey, 1, 2);

    gl->addWidget(labelPlain, 2, 0);
    gl->addWidget(lePlain, 2, 1);

    gl->addWidget(buttonCancel, 3, 1);
    gl->addWidget(buttonCompute, 3, 2);

    this->setLayout(gl);

    QObject::connect(buttonCancel,SIGNAL(clicked()),this,SLOT(close()));
    QObject::connect(buttonBrowseCipher, SIGNAL(clicked()), fdCipher, SLOT(exec()));
    QObject::connect(buttonBrowsePrivateKey, SIGNAL(clicked()), fdPrivateKey, SLOT(exec()));

    QObject::connect(fdCipher, SIGNAL(fileSelected(QString)), leCipher, SLOT(setText(QString)));
    QObject::connect(fdPrivateKey, SIGNAL(fileSelected(QString)), lePrivatekey, SLOT(setText(QString)));

    switch(index){
        case 0:
            QObject::connect(buttonCompute, SIGNAL(clicked()), this, SLOT(computeRSA()));
            break;
        case 1:
            QObject::connect(buttonCompute, SIGNAL(clicked()), this, SLOT(computeRSACRT()));
            break;
        case 2:
            QObject::connect(buttonCompute, SIGNAL(clicked()), this, SLOT(computeElGamal()));
            break;
        case 3:
            QObject::connect(buttonCompute, SIGNAL(clicked()), this, SLOT(computeRabin()));
            break;
        case 4:
            QObject::connect(buttonCompute, SIGNAL(clicked()), this, SLOT(computeRSAOAEP()));
            break;
        default:
            this->close();
            break;
    }
}

void Decipher::computeRSACRT(){
    rePlain = new QRegExp("^[\\w]+$");
    reCipher = new QRegExp("^[\\w|/]+\\.(cipher)$");
    rePrKey = new QRegExp("^[\\w|/]+\\.(prKey)$");
    /*  Dans un soucis de contrôle minimaliste des entrées, nous vérifions, avant toutes opérations, que les
        QLineEdit contienne bien une extension .in pour le fichier d'entrée, une extension .out pour le fi-
        chier de sortie et une extension .key pour le fichier de clé
    */
    if(rePlain->exactMatch(lePlain->text()) && reCipher->exactMatch(leCipher->text()) && rePrKey->exactMatch(lePrivatekey->text())){
        rsa = new RSA();
        rep = rsa->decryptCRT(leCipher->text().toLocal8Bit().constData(), lePrivatekey->text().toLocal8Bit().constData(), lePlain->text().toLocal8Bit().constData());
        if(rep == 1){
            mb = new QMessageBox(this);
            mb->setText("Cannot open one of the given files.");
            mb->setWindowTitle("Information");
            mb->exec();

        }else{
            mb = new QMessageBox(this);
            mb->setWindowTitle("Information");
            mb->setText("Success");
            mb->setWindowTitle("Information");
            mb->exec();
            this->close();
        }
    }
    else{
        if(!rePlain->exactMatch(lePlain->text())){
            mb = new QMessageBox(this);
            mb->setText("The given name doesn't respect the given format.");
            mb->setWindowTitle("Information");
            mb->exec();
            this->close();
        }
        else if(!reCipher->exactMatch(leCipher->text())){
            mb = new QMessageBox(this);
            mb->setText("The given cipher file is wrong.");
            mb->setWindowTitle("Information");
            mb->exec();
            this->close();
        }
        else if(!rePrKey->exactMatch(lePrivatekey->text())){
            mb = new QMessageBox(this);
            mb->setText("The given private key file is wrong.");
            mb->setWindowTitle("Information");
            mb->exec();
            this->close();
        }
    }
}

void Decipher::computeElGamal(){
    rePlain = new QRegExp("^[\\w]+$");
    reCipher = new QRegExp("^[\\w|/]+\\.(cipher)$");
    rePrKey = new QRegExp("^[\\w|/]+\\.(prKey)$");
    /*  Dans un soucis de contrôle minimaliste des entrées, nous vérifions, avant toutes opérations, que les
        QLineEdit contienne bien une extension .in pour le fichier d'entrée, une extension .out pour le fi-
        chier de sortie et une extension .key pour le fichier de clé
    */
    if(rePlain->exactMatch(lePlain->text()) && reCipher->exactMatch(leCipher->text()) && rePrKey->exactMatch(lePrivatekey->text())){
        elGamal = new ElGamal();
        rep = elGamal->decipherElGamal(leCipher->text().toLocal8Bit().constData(), lePrivatekey->text().toLocal8Bit().constData(), lePlain->text().toLocal8Bit().constData());
        if(rep == 1){
            mb = new QMessageBox(this);
            mb->setText("Cannot open one of the given files.");
            mb->setWindowTitle("Information");
            mb->exec();
            this->close();
        }else{
            mb = new QMessageBox(this);
            mb->setWindowTitle("Information");
            mb->setText("Success");
            mb->setWindowTitle("Information");
            mb->exec();
            this->close();
        }
    }
    else{
        if(!rePlain->exactMatch(lePlain->text())){
            mb = new QMessageBox(this);
            mb->setWindowTitle("Information");
            mb->setText("the given name doesn't respect the given format");
            mb->exec();
            this->close();
        }
        else if(!reCipher->exactMatch(leCipher->text())){
            mb = new QMessageBox(this);
            mb->setText("The given cipher file is wrong.");
            mb->setWindowTitle("Information");
            mb->exec();
            this->close();
        }
        else if(!rePrKey->exactMatch(lePrivatekey->text())){
            mb = new QMessageBox(this);
            mb->setText("The given private key file is wrong.");
            mb->setWindowTitle("Information");
            mb->exec();
            this->close();
        }
        else if(!rePrKey->exactMatch(lePrivatekey->text())){
            mb = new QMessageBox(this);
            mb->setWindowTitle("Information");
            mb->setText("The given private key file is wrong.");
            mb->exec();
            this->close();
        }
    }
}

void Decipher::computeRabin(){
    rePlain = new QRegExp("^[\\w]+$");
    reCipher = new QRegExp("^[\\w|/]+\\.(cipher)$");
    rePrKey = new QRegExp("^[\\w|/]+\\.(prKey)$");
    /*  Dans un soucis de contrôle minimaliste des entrées, nous vérifions, avant toutes opérations, que les
        QLineEdit contienne bien une extension .in pour le fichier d'entrée, une extension .out pour le fi-
        chier de sortie et une extension .key pour le fichier de clé
    */
    if(rePlain->exactMatch(lePlain->text()) && reCipher->exactMatch(leCipher->text()) && rePrKey->exactMatch(lePrivatekey->text())){
        rabin = new Rabin();
        rep = rabin->decrypt_Rabin(leCipher->text().toLocal8Bit().constData(),lePlain->text().toLocal8Bit().constData(),lePrivatekey->text().toLocal8Bit().constData());
        if(rep == 1){
            mb = new QMessageBox(this);
            mb->setText("Cannot open one of the given files.");
            mb->setWindowTitle("Information");
            mb->exec();
            this->close();
        }else{
            mb = new QMessageBox(this);
            mb->setWindowTitle("Information");
            mb->setText("Success");
            mb->setWindowTitle("Information");
            mb->exec();
            this->close();
        }
    }
    else{
        if(!rePlain->exactMatch(lePlain->text())){
            mb = new QMessageBox(this);
            mb->setWindowTitle("Information");
            mb->setText("the given name doesn't respect the given format");
            mb->exec();
            this->close();
        }
        else if(!reCipher->exactMatch(leCipher->text())){
            mb = new QMessageBox(this);
            mb->setText("The given cipher file is wrong.");
            mb->setWindowTitle("Information");
            mb->exec();
            this->close();
        }
        else if(!rePrKey->exactMatch(lePrivatekey->text())){
            mb = new QMessageBox(this);
            mb->setText("The given private key file is wrong.");
            mb->setWindowTitle("Information");
            mb->exec();
            this->close();
        }
    }
}

void Decipher::computeRSA() {
    rePlain = new QRegExp("^[\\w]+$");
    reCipher = new QRegExp("^[\\w|/]+\\.(cipher)$");
    rePrKey = new QRegExp("^[\\w|/]+\\.(prKey)$");

    if(rePlain->exactMatch(lePlain->text()) && reCipher->exactMatch(leCipher->text()) && rePrKey->exactMatch(lePrivatekey->text())){
        rsa = new RSA();
        rep = rsa->decrypt(leCipher->text().toLocal8Bit().constData(), lePrivatekey->text().toLocal8Bit().constData(), lePlain->text().toLocal8Bit().constData());
        if(rep == 1){
            mb = new QMessageBox(this);
            mb->setText("Cannot open one of the given files.");
            mb->setWindowTitle("Information");
            mb->exec();
            this->close();
        }else{
            mb = new QMessageBox(this);
            mb->setWindowTitle("Information");
            mb->setText("Success");
            mb->exec();
            this->close();
        }
    }
    else{
        if(!rePlain->exactMatch(lePlain->text())){
            mb = new QMessageBox(this);
            mb->setText("The given name doesn't respect the given format.");
            mb->setWindowTitle("Information");
            mb->exec();
            this->close();
        }
        else if(!reCipher->exactMatch(leCipher->text())){
            mb = new QMessageBox(this);
            mb->setText("The given cipher file is wrong.");
            mb->setWindowTitle("Information");
            mb->exec();
            this->close();
        }
        else if(!rePrKey->exactMatch(lePrivatekey->text())){
            mb = new QMessageBox(this);
            mb->setText("The given private key file is wrong.");
            mb->setWindowTitle("Information");
            mb->exec();
            this->close();
        }
    }
}

void Decipher::computeRSAOAEP(){
    rePlain = new QRegExp("^[\\w]+$");
    reCipher = new QRegExp("^[\\w|/]+\\.(cipher)$");
    rePrKey = new QRegExp("^[\\w|/]+\\.(prKey)$");

    if(rePlain->exactMatch(lePlain->text()) && reCipher->exactMatch(leCipher->text()) && rePrKey->exactMatch(lePrivatekey->text())){
        rsa = new RSA();
        rep = rsa->decryptOAEP(leCipher->text().toLocal8Bit().constData(), lePrivatekey->text().toLocal8Bit().constData(), lePlain->text().toLocal8Bit().constData());
        if(rep == 1){
            mb = new QMessageBox(this);
            mb->setText("Cannot open one of the given files.");
            mb->setWindowTitle("Information");
            mb->exec();
            this->close();

        }else{
            mb = new QMessageBox(this);
            mb->setWindowTitle("Information");
            mb->setText("Success");
            mb->setWindowTitle("Information");
            mb->exec();
            this->close();
        }
    }
    else{
        if(!rePlain->exactMatch(lePlain->text())){
            mb = new QMessageBox(this);
            mb->setText("The given name doesn't respect the given format.");
            mb->setWindowTitle("Information");
            mb->exec();
            this->close();
        }
        else if(!reCipher->exactMatch(leCipher->text())){
            mb = new QMessageBox(this);
            mb->setText("The given cipher file is wrong.");
            mb->setWindowTitle("Information");
            mb->exec();
            this->close();
        }
        else if(!rePrKey->exactMatch(lePrivatekey->text())){
            mb = new QMessageBox(this);
            mb->setText("The given private key file is wrong.");
            mb->setWindowTitle("Information");
            mb->exec();
            this->close();
        }
    }
}
