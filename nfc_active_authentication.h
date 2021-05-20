#ifndef NFCACTIVEAUTHENTICATION_H
#define NFCACTIVEAUTHENTICATION_H

#include <vector>
#include <QByteArray>

class rsa_st;
class NFCActiveAuthentication
{

public:
    NFCActiveAuthentication(rsa_st *publicKey);
    std::vector<uint8_t> decryptMessage(std::vector<uint8_t> &data);

private:
    //std::vector<uint8_t> m_publicKey{};
    rsa_st *m_publicRSAKey{nullptr};


    std::vector<uint8_t> toVector(const QByteArray &data);
    QByteArray dataFromString(const QString &data);
    QString humanReadable(const QByteArray &data);
    QString humanReadable(const std::vector<uint8_t> &data);
    QByteArray dataFromVector(const std::vector<uint8_t> &data);
};

#endif // NFCACTIVEAUTHENTICATION_H
