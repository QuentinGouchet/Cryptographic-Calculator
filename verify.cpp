#include "verify.h"

Verify::Verify() : QDialog(){}

Verify::Verify(int index) : QDialog(){
    this->setFixedSize(800, 400);
    this->setWindowTitle("Verify");

    labelHash = new QLabel("Choose the file which contain the hashed message (*.hash)", this);
    labelSigned = new QLabel("Choose the file which contain the signed message (*.sign)", this);
    labelPuKey = new QLabel("Choose the file which contain the public key (*.puKey)", this);

    buttonBrowseHash = new QPushButton("Browse", this);
    buttonBrowseSigned = new QPushButton("Browse", this);
    buttonBrowsePuKey = new QPushButton("Browse", this);
    buttonCancel = new QPushButton("Cancel", this);
    buttonCompute = new QPushButton("Compute", this);

    leHash = new QLineEdit(this);
    leSigned = new QLineEdit(this);
    lePuKey = new QLineEdit(this);

    fdHash = new QFileDialog(this);
    fdSigned = new QFileDialog(this);
    fdPuKey = new QFileDialog(this);

    fdHash->setDirectory("../ressources/");
    fdSigned->setDirectory("../ressources/");
    fdPuKey->setDirectory("../ressources/");
    fdPuKey->setNameFilter("*.puKey");
    fdSigned->setNameFilter("*.sign");
    fdHash->setNameFilter("*.hash");

    gl = new QGridLayout(this);

    gl->addWidget(labelHash, 0, 0);
    gl->addWidget(leHash, 0, 1);
    gl->addWidget(buttonBrowseHash, 0, 2);

    gl->addWidget(labelSigned, 1, 0);
    gl->addWidget(leSigned, 1, 1);
    gl->addWidget(buttonBrowseSigned, 1, 2);

    gl->addWidget(labelPuKey, 2, 0);
    gl->addWidget(lePuKey, 2, 1);
    gl->addWidget(buttonBrowsePuKey, 2, 2);

    gl->addWidget(buttonCancel, 3, 1);
    gl->addWidget(buttonCompute, 3, 2);

    QObject::connect(buttonCancel, SIGNAL(clicked()), this, SLOT(close()));

    QObject::connect(buttonBrowseHash, SIGNAL(clicked()), fdHash, SLOT(exec()));
    QObject::connect(buttonBrowseSigned, SIGNAL(clicked()), fdSigned, SLOT(exec()));
    QObject::connect(buttonBrowsePuKey, SIGNAL(clicked()), fdPuKey, SLOT(exec()));
    QObject::connect(fdHash, SIGNAL(fileSelected(QString)), leHash, SLOT(setText(QString)));
    QObject::connect(fdSigned, SIGNAL(fileSelected(QString)), leSigned, SLOT(setText(QString)));
    QObject::connect(fdPuKey, SIGNAL(fileSelected(QString)), lePuKey, SLOT(setText(QString)));

    this->setLayout(gl);

    switch(index){
        case 0:
            QObject::connect(buttonCompute, SIGNAL(clicked()), this, SLOT(computeRSA()));
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

void Verify::computeRSA(){
    // La regex accepte uniquement les mots composé de lettres, de chiffres
    // De caractère spéciaux hormis le "." et l'espace (pour éviter de
    // Définir une nouvelle extension.
    rePuKey = new QRegExp("^[\\w|/]+\\.(puKey)$");
    reSign = new QRegExp("^[\\w|/]+\\.(sign)$");
    reHash = new QRegExp("^[\\w|/]+\\.(hash)$");

    if(rePuKey->exactMatch(lePuKey->text()) && reSign->exactMatch(leSigned->text()) && reHash->exactMatch(leHash->text())){
        rsa = new RSA();
        int rep = rsa->verify(leHash->text().toLocal8Bit().constData(), leSigned->text().toLocal8Bit().constData(), lePuKey->text().toLocal8Bit().constData());
        if(rep == 0){
            mb = new QMessageBox(this);
            mb->setText("Success while verifying the signature");
            mb->setWindowTitle("Message");
            mb->exec();
            this->close();
        }
        else if(rep == 1){
            mb = new QMessageBox(this);
            mb->setText("Failed while verifying the signature");
            mb->setWindowTitle("Message");
            mb->exec();
            this->close();
        }else{
            mb = new QMessageBox(this);
            mb->setText("Cannot open one of the given files");
            mb->setWindowTitle("Message");
            mb->exec();
        }
    }
    else{
        if(!reSign->exactMatch(leSigned->text())){
            mb = new QMessageBox(this);
            mb->setText("The given name doesn't respect the given format.");
            mb->setWindowTitle("Message");
            mb->exec();
            this->close();
        }
        else if(!rePuKey->exactMatch(lePuKey->text())){
            mb = new QMessageBox(this);
            mb->setText("The given name doesn't respect the given format.");
            mb->setWindowTitle("Message");
            mb->exec();
            this->close();
        }
        else if(!reHash->exactMatch(leHash->text())){
            mb = new QMessageBox(this);
            mb->setText("The given name doesn't respect the given format.");
            mb->setWindowTitle("Message");
            mb->exec();
            this->close();
        }
    }
}

void Verify::computeElGamal(){
    // La regex accepte uniquement les mots composé de lettres, de chiffres
    // De caractère spéciaux hormis le "." et l'espace (pour éviter de
    // Définir une nouvelle extension.
    rePuKey = new QRegExp("^[\\w|/]+\\.(puKey)$");
    reSign = new QRegExp("^[\\w|/]+\\.(sign)$");
    reHash = new QRegExp("^[\\w|/]+\\.(hash)$");

    if(rePuKey->exactMatch(lePuKey->text()) && reSign->exactMatch(leSigned->text()) && reHash->exactMatch(leHash->text())){
        elGamal = new ElGamal();
        rep = elGamal->verify(leSigned->text().toLocal8Bit().constData(), lePuKey->text().toLocal8Bit().constData(), leHash->text().toLocal8Bit().constData());
        switch(rep){
            case 0:
                mb = new QMessageBox(this);
                mb->setText("Success while verfiying the signature");
                mb->setWindowTitle("Message");
                mb->exec();
                this->close();
                break;
            case 1:
                mb = new QMessageBox(this);
                mb->setText("Failed while verifying the signature");
                mb->setWindowTitle("Message");
                mb->exec();
                this->close();
                break;
            case 2:
                mb = new QMessageBox(this);
                mb->setText("Cannot open one the given files");
                mb->setWindowTitle("Message");
                mb->exec();
                this->close();
                break;
            default :
                this->close();
        }
    }
    else{
        if(!reSign->exactMatch(leSigned->text())){
            mb = new QMessageBox(this);
            mb->setText("The given name doesn't respect the given format.");
            mb->setWindowTitle("Message");
            mb->exec();
            this->close();
        }
        else if(!rePuKey->exactMatch(lePuKey->text())){
            mb = new QMessageBox(this);
            mb->setText("The given name doesn't respect the given format.");
            mb->setWindowTitle("Message");
            mb->exec();
            this->close();
        }
        else if(!reHash->exactMatch(leHash->text())){
            mb = new QMessageBox(this);
            mb->setText("The given name doesn't respect the given format.");
            mb->setWindowTitle("Message");
            mb->exec();
            this->close();
        }
    }
}

void Verify::computeDSA(){
    // La regex accepte uniquement les mots composé de lettres, de chiffres
    // De caractère spéciaux hormis le "." et l'espace (pour éviter de
    // Définir une nouvelle extension.
    rePuKey = new QRegExp("^[\\w|/]+\\.(puKey)$");
    reSign = new QRegExp("^[\\w|/]+\\.(sign)$");
    reHash = new QRegExp("^[\\w|/]+\\.(hash)$");

    if(rePuKey->exactMatch(lePuKey->text()) && reSign->exactMatch(leSigned->text()) && reHash->exactMatch(leHash->text())){
        dsa = new DSA();
        rep = dsa->verify(leSigned->text().toLocal8Bit().constData(), lePuKey->text().toLocal8Bit().constData(), leHash->text().toLocal8Bit().constData());
        switch(rep){
            case 0:
                mb = new QMessageBox(this);
                mb->setText("Success while verfiying the signature");
                mb->setWindowTitle("Message");
                mb->exec();
                this->close();
                break;
            case 1:
                mb = new QMessageBox(this);
                mb->setText("Failed while verifying the signature");
                mb->setWindowTitle("Message");
                mb->exec();
                this->close();
                break;
            case 2:
                mb = new QMessageBox(this);
                mb->setText("Cannot open one of the given files");
                mb->setWindowTitle("Message");
                mb->exec();
                break;
            default :
                this->close();
        }
    }
    else{
        if(!reSign->exactMatch(leSigned->text())){
            mb = new QMessageBox(this);
            mb->setText("The given name doesn't respect the given format.");
            mb->setWindowTitle("Message");
            mb->exec();
            this->close();
        }
        else if(!rePuKey->exactMatch(lePuKey->text())){
            mb = new QMessageBox(this);
            mb->setText("The given name doesn't respect the given format.");
            mb->setWindowTitle("Message");
            mb->exec();
            this->close();
        }
        else if(!reHash->exactMatch(leHash->text())){
            mb = new QMessageBox(this);
            mb->setText("The given name doesn't respect the given format.");
            mb->setWindowTitle("Message");
            mb->exec();
            this->close();
        }
    }
}
