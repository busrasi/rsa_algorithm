#include <QCoreApplication>

#include <rsa_manager.h>
#include <nfc_active_authentication.h>

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    RSAManager rsaManager{};
    auto msg = rsaManager.encryptedTestMessage();

    NFCActiveAuthentication authenticator(rsaManager.publicRSAKey());
    authenticator.decryptMessage(msg);

    return a.exec();
}
