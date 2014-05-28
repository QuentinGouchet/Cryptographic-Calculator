#include "hash.h"

Hash::Hash() : QDialog() {}

Hash::Hash(int index): QDialog()
{
    setFixedSize(800, 400);
    this->setWindowTitle("Hash");

    labelPlain = new QLabel("Choose file to hash :");
    labelHash = new QLabel("Choose a name for the hash file :");

    buttonHash = new QPushButton("Hash");
    buttonCancel = new QPushButton("Cancel");
    buttonBrowse = new QPushButton("Browse");

    lePlain = new QLineEdit(this);
    leHash = new QLineEdit(this);

    fdPlain = new QFileDialog(this);
    fdPlain->setDirectory("../ressources/");

    gl = new QGridLayout(this);

    gl->addWidget(labelPlain, 0, 0);
    gl->addWidget(lePlain, 0, 1);
    gl->addWidget(buttonBrowse, 0, 2);

    gl->addWidget(labelHash, 1, 0);
    gl->addWidget(leHash, 1, 1);

    gl->addWidget(buttonCancel, 2, 1);
    gl->addWidget(buttonHash, 2, 2);

    this->setLayout(gl);

    QObject::connect(buttonCancel,SIGNAL(clicked()),this,SLOT(close()));
    QObject::connect(buttonBrowse,SIGNAL(clicked()),fdPlain,SLOT(exec()));

    QObject::connect(fdPlain,SIGNAL(fileSelected(QString)),lePlain,SLOT(setText(QString)));

    switch(index){
        case 0:
            QObject::connect(buttonHash, SIGNAL(clicked()), this, SLOT(hashSHA256()));
            break;
        case 1:
            QObject::connect(buttonHash, SIGNAL(clicked()), this, SLOT(hashSHA512()));
            break;
         case 2:
            QObject::connect(buttonHash, SIGNAL(clicked()), this, SLOT(hashSHA1()));
            break;
        default:
            this->close();
            break;
    }
}

void Hash::hashSHA256() {
    // La regex accepte uniquement les mots composé de lettres, de chiffres
    // De caractère spéciaux hormis le "." et l'espace (pour éviter de
    // Définir une nouvelle extension.
    reFileName = new QRegExp("([\\w]+)");

    if(reFileName->exactMatch(leHash->text())){
        mySha = new MySha();
        rep = mySha->computeSha256(lePlain->text().toLocal8Bit().data(), leHash->text().toLocal8Bit().constData());
        if(rep == 1){
            mb = new QMessageBox(this);
            mb->setText("Cannot open one of the given files.");
            mb->setWindowTitle("Message");
            mb->exec();
        }else{
            mb = new QMessageBox(this);
            mb->setText("Success");
            mb->setWindowTitle("Message");
            mb->exec();
            this->close();
        }
    }
    else{
        mb = new QMessageBox(this);
        mb->setText("The given name doesn't respect the given format.");
        mb->setWindowTitle("Message");
        mb->exec();
    }
}

void Hash::hashSHA512() {
    // La regex accepte uniquement les mots composé de lettres, de chiffres
    // De caractère spéciaux hormis le "." et l'espace (pour éviter de
    // Définir une nouvelle extension.
    reFileName = new QRegExp("([\\w]+)");

    if(reFileName->exactMatch(leHash->text())){
        mySha = new MySha();
        rep = mySha->computeSha512(lePlain->text().toLocal8Bit().data(), leHash->text().toLocal8Bit().constData());
        if(rep == 1){
            mb = new QMessageBox(this);
            mb->setText("Cannot open one of the given files.");
            mb->setWindowTitle("Message");
            mb->exec();
        }else{
            mb = new QMessageBox(this);
            mb->setText("Success");
            mb->setWindowTitle("Message");
            mb->exec();
            this->close();
        }
    }
    else{
        mb = new QMessageBox(this);
        mb->setText("The given name doesn't respect the given format.");
        mb->setWindowTitle("Message");
        mb->exec();
    }
}

void Hash::hashSHA1() {
    // La regex accepte uniquement les mots composé de lettres, de chiffres
    // De caractère spéciaux hormis le "." et l'espace (pour éviter de
    // Définir une nouvelle extension.
    reFileName = new QRegExp("([\\w]+)");

    if(reFileName->exactMatch(leHash->text())){
        mySha = new MySha();
        rep = mySha->sha1(lePlain->text().toLocal8Bit().data(), leHash->text().toLocal8Bit().constData());
        if(rep == 1){
            mb = new QMessageBox(this);
            mb->setText("Cannot open one of the given files.");
            mb->setWindowTitle("Message");
            mb->exec();
        }else{
            mb = new QMessageBox(this);
            mb->setText("Success");
            mb->setWindowTitle("Message");
            mb->exec();
            this->close();
        }
    }
    else{
        mb = new QMessageBox(this);
        mb->setText("The given name doesn't respect the given format.");
        mb->setWindowTitle("Message");
        mb->exec();
    }
}

