#include "generatekey.h"

GenerateKey::GenerateKey() : QDialog() {}

void GenerateKey::setLengthKey(QString newLength){
    int newIntLength = atoi(newLength.toLocal8Bit().data());
    this->lengthKey = newIntLength;
}

/*
    0 - RSA
    1 - RSA-OAEP
    2 - RSA-CRT
    3 - EL GAMAL
    4 - RABIN
*/
GenerateKey::GenerateKey(int index): QDialog()
{
    setFixedSize(800, 400);
    this->setWindowTitle("Generate Key");

    labelLengthKey = new QLabel("Choose the length of the key :");
    labelFileNameKeys = new QLabel("Choose a name for the key files :");

    buttonCancel = new QPushButton("Cancel", this);
    buttonGenerate = new QPushButton("Generate", this);

    leLenghtKey = new QLineEdit(this);
    leFileNameKeys = new QLineEdit(this);

    gl = new QGridLayout(this);

    gl->addWidget(labelLengthKey, 1, 0);
    gl->addWidget(leLenghtKey, 1, 2);

    gl->addWidget(labelFileNameKeys, 2, 0);
    gl->addWidget(leFileNameKeys, 2, 2);

    gl->addWidget(buttonCancel, 3, 1);
    gl->addWidget(buttonGenerate, 3, 2);

    this->setLayout(gl);

    QObject::connect(buttonCancel,SIGNAL(clicked()),this,SLOT(close()));
    QObject::connect(leLenghtKey, SIGNAL(textChanged(QString)), this, SLOT(setLengthKey(QString)));

    switch(index){
        case 0:
            QObject::connect(buttonGenerate, SIGNAL(clicked()), this, SLOT(generateRSA()));
            break;
        case 1:
            QObject::connect(buttonGenerate, SIGNAL(clicked()), this, SLOT(generateElGamal()));
            break;
        case 2:
            QObject::connect(buttonGenerate, SIGNAL(clicked()), this, SLOT(generateRabin()));
            break;
        case 3:
            QObject::connect(buttonGenerate, SIGNAL(clicked()), this, SLOT(generateDSA()));
            leLenghtKey->setEnabled(false);
            break;
        default:
            this->close();
            break;
    }
}

void GenerateKey::generateRSA() {
    // La regex accepte uniquement les mots composé de lettres, de chiffres
    // De caractère spéciaux hormis le "." et l'espace (pour éviter de
    // Définir une nouvelle extension.
    reFileName = new QRegExp("([\\w]+)");
    // La regex n'accepte que les nombres (aucune restriction sur la taille)
    reLenghtKey = new QRegExp("([\\d]+)");

    if(reLenghtKey->exactMatch(leLenghtKey->text()) && reFileName->exactMatch(leFileNameKeys->text())){
        rsa = new RSA();
        rep = rsa->generateKey(this->getLengthKey(), leFileNameKeys->text().toLocal8Bit().constData());
        if(rep == 1){
            mb = new QMessageBox(this);
            mb->setText("Cannot open one of the given files");
            mb->exec();

        }else{
            mb = new QMessageBox(this);
            mb->setText("Success");
            mb->exec();
            this->close();
        }
    }
    else{
        if(!reLenghtKey->exactMatch(leLenghtKey->text())){
            mb = new QMessageBox(this);
            mb->setText("this input only accepts number");
            mb->exec();
        }
        else if(!reFileName->exactMatch(leFileNameKeys->text())){
            mb = new QMessageBox(this);
            mb->setText("the given name doesn't respect the given format");
            mb->exec();
        }
    }
}

void GenerateKey::generateElGamal() {
    // La regex accepte uniquement les mots composé de lettres, de chiffres
    // De caractère spéciaux hormis le "." et l'espace (pour empécher
    // L'utilisateur de définir une nouvelle extension.
    reFileName = new QRegExp("([\\w]+)");
    // La regex n'accepte que les nombres (aucune restriction sur la taille)
    reLenghtKey = new QRegExp("(\\d+)");

    if(reLenghtKey->exactMatch(leLenghtKey->text()) && reFileName->exactMatch(leFileNameKeys->text())){
        elGamal = new ElGamal();
        rep = elGamal->generateKey(this->getLengthKey(), leFileNameKeys->text().toLocal8Bit().constData());
        if(rep == 1){
            mb = new QMessageBox(this);
            mb->setText("Cannot open one of the given files");
            mb->exec();

        }else{
            mb = new QMessageBox(this);
            mb->setText("Success");
            mb->exec();
            this->close();
        }
    }
    else{
        if(!reLenghtKey->exactMatch(leLenghtKey->text())){
            mb = new QMessageBox(this);
            mb->setText("this input only accepts number");
            mb->exec();
        }
        else if(!reFileName->exactMatch(leFileNameKeys->text())){
            mb = new QMessageBox(this);
            mb->setText("the given name doesn't respect the given format");
            mb->exec();
        }
    }
}

void GenerateKey::generateRabin() {
    // La regex accepte uniquement les mots composé de lettres, de chiffres
    // De caractère spéciaux hormis le "." et l'espace (pour éviter de
    // Définir une nouvelle extension.
    reFileName = new QRegExp("([\\w]+)");
    // La regex n'accepte que les nombres (aucune restriction sur la taille)
    reLenghtKey = new QRegExp("(\\d+)");

    if(reLenghtKey->exactMatch(leLenghtKey->text()) && reFileName->exactMatch(leFileNameKeys->text())){
        rabin = new Rabin();
        rep = rabin->generateKey(this->getLengthKey(), leFileNameKeys->text().toLocal8Bit().constData());
        if(rep == 1){
            mb = new QMessageBox(this);
            mb->setText("Cannot open one of the given files");
            mb->exec();

        }else{
            mb = new QMessageBox(this);
            mb->setText("Success");
            mb->exec();
            this->close();
        }
    }
    else{
        if(!reLenghtKey->exactMatch(leLenghtKey->text())){
            mb = new QMessageBox(this);
            mb->setText("this input only accepts number");
            mb->exec();
        }
        else if(!reFileName->exactMatch(leFileNameKeys->text())){
            mb = new QMessageBox(this);
            mb->setText("the given name doesn't respect the given format");
            mb->exec();
        }
    }
}

void GenerateKey::generateDSA(){
    // La regex accepte uniquement les mots composé de lettres, de chiffres
    // De caractère spéciaux hormis le "." et l'espace (pour éviter de
    // Définir une nouvelle extension.
    reFileName = new QRegExp("([\\w]+)");

    if(reFileName->exactMatch(leFileNameKeys->text())){
        dsa = new DSA();
        rep = dsa->generateKey(leFileNameKeys->text().toLocal8Bit().constData());
        if(rep == 1){
            mb = new QMessageBox(this);
            mb->setText("Cannot open one of the given files");
            mb->exec();

        }else{
            mb = new QMessageBox(this);
            mb->setText("Success");
            mb->exec();
            this->close();
        }
    }
    else{
        if(!reLenghtKey->exactMatch(leLenghtKey->text())){
            mb = new QMessageBox(this);
            mb->setText("this input only accepts number");
            mb->exec();
        }
        else if(!reFileName->exactMatch(leFileNameKeys->text())){
            mb = new QMessageBox(this);
            mb->setText("the given name doesn't respect the given format");
            mb->exec();
        }
    }
}
