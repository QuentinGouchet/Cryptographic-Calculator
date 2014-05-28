#include "cipher.h"

Cipher::Cipher(): QDialog() {}

/*
    0 - "RSA"
    1 - "EL GAMAL"
    2 - "RABIN"
    3 - "RSA-OAEP"
*/

Cipher::Cipher(int index): QDialog(){
    setFixedSize(800, 400);
    this->setWindowTitle("Cipher");

    labelPlain = new QLabel("Choose file to cipher :",this);
    labelCipher = new QLabel("Name the output file :",this);
    labelPublicKey = new QLabel("Choose which key to use :",this);

    buttonBrowsePlain = new QPushButton("Browse", this);
    buttonBrowsePublicKey = new QPushButton("Browse", this);
    buttonCancel = new QPushButton("Cancel", this);
    buttonCompute = new QPushButton("Compute", this);

    lePlain = new QLineEdit(this);
    leCipher = new QLineEdit(this);
    lePublicKey = new QLineEdit(this);

    fdPlain = new QFileDialog(this);
    fdPublicKey = new QFileDialog(this);

    fdPlain->setDirectory("../ressources/");
    fdPublicKey->setDirectory("../ressources/");

    fdPublicKey->setNameFilter("*.puKey");

    gl = new QGridLayout(this);

    gl->addWidget(labelPlain, 0, 0);
    gl->addWidget(lePlain, 0, 1);
    gl->addWidget(buttonBrowsePlain, 0, 2);

    gl->addWidget(labelPublicKey, 1, 0);
    gl->addWidget(lePublicKey, 1, 1);
    gl->addWidget(buttonBrowsePublicKey, 1, 2);

    gl->addWidget(labelCipher, 2, 0);
    gl->addWidget(leCipher, 2, 1);

    gl->addWidget(buttonCancel, 3, 1);
    gl->addWidget(buttonCompute, 3, 2);

    this->setLayout(gl);

    QObject::connect(buttonCancel,SIGNAL(clicked()),this,SLOT(close()));
    QObject::connect(buttonBrowsePlain, SIGNAL(clicked()), fdPlain, SLOT(exec()));
    QObject::connect(buttonBrowsePublicKey, SIGNAL(clicked()), fdPublicKey, SLOT(exec()));

    QObject::connect(fdPlain, SIGNAL(fileSelected(QString)), lePlain, SLOT(setText(QString)));
    QObject::connect(fdPublicKey, SIGNAL(fileSelected(QString)), lePublicKey, SLOT(setText(QString)));

    switch(index){
        case 0:
            QObject::connect(buttonCompute, SIGNAL(clicked()), this, SLOT(computeRSA()));
            break;
        case 1:
            QObject::connect(buttonCompute, SIGNAL(clicked()), this, SLOT(computeElGamal()));
            break;
        case 2:
            QObject::connect(buttonCompute, SIGNAL(clicked()), this, SLOT(computeRabin()));
            break;
        case 3:
            QObject::connect(buttonCompute, SIGNAL(clicked()), this, SLOT(computeRSAOAEP()));
            break;
        default:
            this->close();
            break;
    }
}

void Cipher::computeRSA() {
    reCipher = new QRegExp("([\\w]+)");
    rePuKey = new QRegExp("^[\\w|/]+\\.(puKey)$");

    /*
        Dans un soucis de contrôle minimaliste des entrées, nous vérifions, avant toutes opérations, que les
        QLineEdit contienne bien une extension .in pour le fichier d'entrée, une extension .out pour le fi-
        chier de sortie et une extension .key pour le fichier de clé
    */
    if(reCipher->exactMatch(leCipher->text()) && rePuKey->exactMatch(lePublicKey->text())){
        rsa = new RSA();
        rep = rsa->encrypt(lePlain->text().toLocal8Bit().constData(), lePublicKey->text().toLocal8Bit().constData(), leCipher->text().toLocal8Bit().constData());
        if(rep == 1){
            mb = new QMessageBox(this);
            mb->setWindowTitle("Information");
            mb->setText("Cannot open one of the given files");
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
            mb->setWindowTitle("Information");
            mb->setText("The given plain file is wrong.");
            mb->exec();
            this->close();
        }
        else if(!rePuKey->exactMatch(lePublicKey->text())){
            mb = new QMessageBox(this);
            mb->setWindowTitle("Information");
            mb->setText("The given public key is wrong.");
            mb->exec();

        }
        else if(!rePuKey->exactMatch(lePublicKey->text())){
            mb = new QMessageBox(this);
            mb->setWindowTitle("Information");
            mb->setText("the given public key is wrong");
            mb->exec();
            this->close();
        }
        else if(!reCipher->exactMatch(leCipher->text())){
            mb = new QMessageBox(this);
            mb->setWindowTitle("Information");
            mb->setText("The given name doesn't respect the given format.");
            mb->exec();
            this->close();
        }
    }
}

void Cipher::computeElGamal() {
    reCipher = new QRegExp("([\\w]+)");
    rePuKey = new QRegExp("^[\\w|/]+\\.(puKey)$");

    /*
        Dans un soucis de contrôle minimaliste des entrées, nous vérifions, avant toutes opérations, que les
        QLineEdit contienne bien une extension .in pour le fichier d'entrée, une extension .out pour le fi-
        chier de sortie et une extension .key pour le fichier de clé
    */
    if(reCipher->exactMatch(leCipher->text()) && rePuKey->exactMatch(lePublicKey->text())){
        elGamal = new ElGamal();
        rep = elGamal->cipherElGamal(lePlain->text().toLocal8Bit().constData(),lePublicKey->text().toLocal8Bit().constData(),leCipher->text().toLocal8Bit().constData());
        if(rep == 1){
            mb = new QMessageBox(this);
            mb->setWindowTitle("Information");
            mb->setText("Cannot open one of the given files");
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
            mb->setWindowTitle("Information");
            mb->setText("The given plain file is wrong.");
            mb->exec();
            this->close();
        }
        else if(!rePuKey->exactMatch(lePublicKey->text())){
            mb = new QMessageBox(this);
            mb->setWindowTitle("Information");
            mb->setText("The given public key is wrong.");
            mb->exec();
            this->close();
        }
        else if(!rePuKey->exactMatch(lePublicKey->text())){
            mb = new QMessageBox(this);
            mb->setWindowTitle("Information");
            mb->setText("the given public key is wrong");
            mb->exec();
            this->close();
        }
        else if(!reCipher->exactMatch(leCipher->text())){
            mb = new QMessageBox(this);
            mb->setWindowTitle("Information");
            mb->setText("The given name doesn't respect the given format.");
            mb->exec();
            this->close();
        }
    }
}

void Cipher::computeRabin(){
    reCipher = new QRegExp("([\\w]+)");
    rePuKey = new QRegExp("^[\\w|/]+\\.(puKey)$");

    /*
        Dans un soucis de contrôle minimaliste des entrées, nous vérifions, avant toutes opérations, que les
        QLineEdit contienne bien une extension .in pour le fichier d'entrée, une extension .out pour le fi-
        chier de sortie et une extension .key pour le fichier de clé
    */
    if(reCipher->exactMatch(leCipher->text()) && rePuKey->exactMatch(lePublicKey->text())){
        rabin = new Rabin();
        rep = rabin->encrypt_Rabin(lePlain->text().toLocal8Bit().constData(),leCipher->text().toLocal8Bit().constData(),lePublicKey->text().toLocal8Bit().constData());
        if(rep == 1){
            mb = new QMessageBox(this);
            mb->setWindowTitle("Information");
            mb->setText("Cannot open one of the given files.");
            mb->exec();
            this->close();

        }else{
            mb = new QMessageBox(this);
            mb->setText("Success");
            mb->setWindowTitle("Information");
            mb->exec();
            this->close();
        }
    }
    else{
        if(!rePuKey->exactMatch(lePublicKey->text())){
            mb = new QMessageBox(this);
            mb->setText("The given public key is wrong.");
            mb->setWindowTitle("Information");
            mb->exec();
            this->close();
        }
        else if(!rePuKey->exactMatch(lePublicKey->text())){
            mb = new QMessageBox(this);
            mb->setText("The given public key is wrong.");
            mb->setWindowTitle("Information");
            mb->exec();
            this->close();
        }
        else if(!reCipher->exactMatch(leCipher->text())){
            mb = new QMessageBox(this);
            mb->setText("The given name doesn't respect the format.");
            mb->setWindowTitle("Information");
            mb->exec();
            this->close();
        }
    }
}

void Cipher::computeRSAOAEP(){
    rePlain = new QRegExp("^[\\w|/]+\\.(plain)$");
    reCipher = new QRegExp("([\\w]+)");
    rePuKey = new QRegExp("^[\\w|/]+\\.(puKey)$");

    /*
        Dans un soucis de contrôle minimaliste des entrées, nous vérifions, avant toutes opérations, que les
        QLineEdit contienne bien une extension .in pour le fichier d'entrée, une extension .out pour le fi-
        chier de sortie et une extension .key pour le fichier de clé
    */
    if(rePlain->exactMatch(lePlain->text()) && reCipher->exactMatch(leCipher->text()) && rePuKey->exactMatch(lePublicKey->text())){
        rsa = new RSA();
        rep = rsa->encryptOAEP(lePlain->text().toLocal8Bit().constData(), lePublicKey->text().toLocal8Bit().constData(), leCipher->text().toLocal8Bit().constData());
        if(rep == 1){
            mb = new QMessageBox(this);
            mb->setText("Cannot open one of the given files.");
            mb->setWindowTitle("Information");
            mb->setText("Cannot open one of the given files");
            mb->exec();

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
          mb->setText("The given plain file is wrong.");
          mb->setWindowTitle("Information");
          mb->exec();
          this->close();
        }
        else if(!rePuKey->exactMatch(lePublicKey->text())){
          mb = new QMessageBox(this);
          mb->setText("The given public key is wrong.");
          mb->setWindowTitle("Information");
          mb->exec();
          this->close();
        }
        else if(!reCipher->exactMatch(leCipher->text())){
          mb = new QMessageBox(this);
          mb->setText("The given name doesn't respect the given format.");
          mb->setWindowTitle("Information");
          mb->exec();
          this->close();
        }
    }
}
