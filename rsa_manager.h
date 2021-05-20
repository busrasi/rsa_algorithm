#ifndef RSAMANAGER_H
#define RSAMANAGER_H

#include <vector>
#include <QByteArray>

class rsa_st;

class RSAManager
{
public:
    RSAManager();
    ~RSAManager();

    std::vector<uint8_t> encryptedTestMessage() const;
    rsa_st *publicRSAKey() const;

private:
    //Encrypted Test Message
    std::vector<uint8_t> m_encryptedTestMessage{};

    rsa_st* m_privateRSAKey{nullptr};
    rsa_st* m_publicRSAKey{nullptr};

    std::vector<uint8_t> toVector(const QByteArray &data);
    QByteArray dataFromString(const QString &data);
    QString humanReadable(const QByteArray &data);
    QString humanReadable(const std::vector<uint8_t> &data);
    QByteArray dataFromVector(const std::vector<uint8_t> &data);

};

#endif // RSAMANAGER_H
