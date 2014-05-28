#include "sign.h"

Sign::Sign() : QDialog()
{
    setFixedSize(300, 300);
}

Sign::Sign(int index): QDialog()
{
    setFixedSize(800, 400);
    this->setWindowTitle("Sign");

    labelHash = new QLabel("Choose the file to sign (*.hash) :", this);
    labelPrKey = new QLabel("Choose the file which contain the private key (*.prKey) :", this);
    labelPuKey = new QLabel("Choose the file which contain the public key (*.puKey) :", this);
    labelFileNameSign = new QLabel("Choose a name for the signed file :");

    buttonBrowseHash = new QPushButton("Browse", this);
    buttonBrowsePrKey = new QPushButton("Browse", this);
    buttonBrowsePuKey = new QPushButton("Browse",this);
    buttonCancel = new QPushButton("Cancel", this);
    buttonCompute = new QPushButton("Compute", this);

    leHash = new QLineEdit(this);
    lePrKey = new QLineEdit(this);
    lePuKey = new QLineEdit(this);
    leFileNameSign = new QLineEdit(this);

    fdHash = new QFileDialog(this);
    fdPrKey = new QFileDialog(this);
    fdPuKey = new QFileDialog(this);

    fdHash->setDirectory("../ressources/");
    fdPuKey->setDirectory("../ressources/");
    fdPrKey->setDirectory("../ressources/");
    fdPrKey->setNameFilter("*.prKey");
    fdPuKey->setNameFilter("*.puKey");
    fdHash->setNameFilter("*.hash");

    gl = new QGridLayout(this);

    gl->addWidget(labelHash, 0, 0);
    gl->addWidget(leHash, 0, 1);
    gl->addWidget(buttonBrowseHash, 0, 2);

    gl->addWidget(labelPrKey, 1, 0);
    gl->addWidget(lePrKey, 1, 1);
    gl->addWidget(buttonBrowsePrKey, 1, 2);

    gl->addWidget(labelPuKey, 2, 0);
    gl->addWidget(lePuKey, 2, 1);
    gl->addWidget(buttonBrowsePuKey, 2, 2);

    gl->addWidget(labelFileNameSign, 3, 0);
    gl->addWidget(leFileNameSign, 3, 1);

    gl->addWidget(buttonCancel, 4, 1);
    gl->addWidget(buttonCompute, 4, 2);

    this->setLayout(gl);

    QObject::connect(buttonCancel,SIGNAL(clicked()),this,SLOT(close()));
    QObject::connect(buttonBrowseHash, SIGNAL(clicked()), fdHash, SLOT(exec()));
    QObject::connect(buttonBrowsePrKey, SIGNAL(clicked()), fdPrKey, SLOT(exec()));
    QObject::connect(buttonBrowsePuKey, SIGNAL(clicked()), fdPuKey, SLOT(exec()));

    QObject::connect(fdHash, SIGNAL(fileSelected(QString)), leHash, SLOT(setText(QString)));
    QObject::connect(fdPrKey, SIGNAL(fileSelected(QString)), lePrKey, SLOT(setText(QString)));
    QObject::connect(fdPuKey, SIGNAL(fileSelected(QString)), lePuKey, SLOT(setText(QString)));

    switch(index){
        case 0:
            QObject::connect(buttonCompute, SIGNAL(clicked()), this, SLOT(computeRSA()));
            buttonBrowsePuKey->setEnabled(false);
            lePuKey->setEnabled(false);
            break;
        case 1:
            QObject::connect(buttonCompute, SIGNAL(clicked()), this, SLOT(computeElGamal()));
            break;
        case 2:
            QObject::connect(buttonCompute, SIGNAL(clicked()), this, SLOT(computeDSA()));
            break;
        default:
            this->close();
    }
}

void Sign::computeRSA(){
    // La regex accepte uniquement les mots composé de lettres, de chiffres
    // De caractère spéciaux hormis le "." et l'espace (pour éviter de
    // Définir une nouvelle extension.
    reFileName = new QRegExp("[\\w]+");
    rePrKey = new QRegExp("^[\\w|/]+\\.(prKey)$");
    reHash = new QRegExp("^[\\w|/]+\\.(hash)$");

    if(reFileName->exactMatch(leFileNameSign->text()) && rePrKey->exactMatch(lePrKey->text()) && reHash->exactMatch(leHash->text())){
        rsa = new RSA();
        rep = rsa->sign(leHash->text().toLocal8Bit().constData(), lePrKey->text().toLocal8Bit().constData(), leFileNameSign->text().toLocal8Bit().constData());
        if(rep == 1){
            mb = new QMessageBox(this);
            mb->setText("Cannot open one of the given files");
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
        if(!reFileName->exactMatch(leFileNameSign->text())){
            mb = new QMessageBox(this);
            mb->setText("The given name doesn't respect the given format.");
            mb->setWindowTitle("Message");
            mb->exec();
            this->close();
        }
        else if(!rePrKey->exactMatch(lePrKey->text())){
            mb = new QMessageBox(this);
            mb->setText("The given private key file is wrong.");
            mb->setWindowTitle("Message");
            mb->exec();
            this->close();
        }
        else if(!reHash->exactMatch(leHash->text())){
            mb = new QMessageBox(this);
            mb->setText("The given hash file is wrong.");
            mb->setWindowTitle("Message");
            mb->exec();
            this->close();
        }
    }
}

void Sign::computeElGamal(){
    // La regex accepte uniquement les mots composé de lettres, de chiffres
    // De caractère spéciaux hormis le "." et l'espace (pour éviter de
    // Définir une nouvelle extension.
    reFileName = new QRegExp("[\\w]+");
    rePrKey = new QRegExp("^[\\w|/]+\\.(prKey)$");
    reHash = new QRegExp("^[\\w|/]+\\.(hash)$");

    if(reFileName->exactMatch(leFileNameSign->text()) && rePrKey->exactMatch(lePrKey->text()) && reHash->exactMatch(leHash->text()) && rePuKey->exactMatch(lePuKey->text())){
        elGamal = new ElGamal();
        rep = elGamal->sign(leHash->text().toLocal8Bit().constData(), lePrKey->text().toLocal8Bit().constData(), leFileNameSign->text().toLocal8Bit().constData());
        if(rep == 1){
            mb = new QMessageBox(this);
            mb->setText("Cannot open one of the given files");
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
        if(!reFileName->exactMatch(leFileNameSign->text())){
            mb = new QMessageBox(this);
            mb->setText("The given name doesn't respect the given format.");
            mb->setWindowTitle("Message");
            mb->exec();
            this->close();
        }
        else if(!rePrKey->exactMatch(lePrKey->text())){
            mb = new QMessageBox(this);
            mb->setText("The given private key file is wrong.");
            mb->setWindowTitle("Message");
            mb->exec();
            this->close();
        }
        else if(!rePuKey->exactMatch(lePuKey->text())){
            mb = new QMessageBox(this);
            mb->setText("The given public key file is wrong.");
            mb->setWindowTitle("Message");
            mb->exec();
            this->close();
        }
        else if(!reHash->exactMatch(leHash->text())){
            mb = new QMessageBox(this);
            mb->setText("The given hash file is wrong.");
            mb->setWindowTitle("Message");
            mb->exec();
            this->close();
        }
    }
}

void Sign::computeDSA(){
    // La regex accepte uniquement les mots composé de lettres, de chiffres
    // De caractère spéciaux hormis le "." et l'espace (pour éviter de
    // Définir une nouvelle extension.
    reFileName = new QRegExp("[\\w]+");
    rePrKey = new QRegExp("^[\\w|/]+\\.(prKey)$");
    reHash = new QRegExp("^[\\w|/]+\\.(hash)$");
    rePuKey = new QRegExp("^[\\w|/]+\\.(puKey)$");

    if(reFileName->exactMatch(leFileNameSign->text()) && rePrKey->exactMatch(lePrKey->text()) && reHash->exactMatch(leHash->text()) && rePuKey->exactMatch(lePuKey->text())){
        dsa = new DSA();
        rep = dsa->sign(leHash->text().toLocal8Bit().constData(), lePuKey->text().toLocal8Bit().constData(), lePrKey->text().toLocal8Bit().constData(), leFileNameSign->text().toLocal8Bit().constData());
        if(rep == 1){
            mb = new QMessageBox(this);
            mb->setText("Cannot open one of the given files");
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
        if(!reFileName->exactMatch(leFileNameSign->text())){
            mb = new QMessageBox(this);
            mb->setText("The given name doesn't respect the given format.");
            mb->setWindowTitle("Message");
            mb->exec();
            this->close();
        }
        else if(!rePrKey->exactMatch(lePrKey->text())){
            mb = new QMessageBox(this);
            mb->setText("The given private key file is wrong.");
            mb->setWindowTitle("Message");
            mb->exec();
            this->close();
        }
        else if(!rePuKey->exactMatch(lePuKey->text())){
            mb = new QMessageBox(this);
            mb->setText("The given public key file is wrong.");
            mb->setWindowTitle("Message");
            mb->exec();
            this->close();
        }
        else if(!reHash->exactMatch(leHash->text())){
            mb = new QMessageBox(this);
            mb->setText("The given hash file is wrong.");
            mb->setWindowTitle("Message");
            mb->exec();
            this->close();
        }
    }
}
