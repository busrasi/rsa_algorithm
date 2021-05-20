#include <QCoreApplication>

#include <rsa_manager.h>
#include <nfc_active_authentication.h>

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    RSAManager rsaManager{};

//    NFCActiveAuthentication authenticator();

    return a.exec();
}
