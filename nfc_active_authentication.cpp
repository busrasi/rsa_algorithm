#include "nfc_active_authentication.h"
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <QDebug>
NFCActiveAuthentication::NFCActiveAuthentication(rsa_st *publicKey)
    : m_publicRSAKey(publicKey)

{
}

std::vector<uint8_t> NFCActiveAuthentication::decryptMessage(std::vector<uint8_t> &data)
{
    qDebug() << __LINE__ << __PRETTY_FUNCTION__ << "enc msg: " << humanReadable(dataFromVector(data));
    qDebug() << m_publicRSAKey;
    std::vector<uint8_t> decryptedData{};
    decryptedData.resize(data.size());
    auto decResult = RSA_public_decrypt(RSA_size(m_publicRSAKey), data.data() ,decryptedData.data(), m_publicRSAKey, RSA_PKCS1_PADDING);
    qDebug() << __LINE__ << __PRETTY_FUNCTION__ << "decresult: " << decResult;
    return std::vector<uint8_t> {};
}


std::vector<uint8_t> NFCActiveAuthentication::toVector(const QByteArray &data)
{
    std::vector<uint8_t> vec{};
    for(auto it = data.begin(); it != data.end(); it++){
        vec.push_back(*it);
    }
    return vec;
}

QByteArray NFCActiveAuthentication::dataFromString(const QString &data)
{
    return QByteArray::fromHex(data.toUpper().toLatin1());
}

QString NFCActiveAuthentication::humanReadable(const QByteArray &data)
{
    return data.toHex().toUpper();
}

QString NFCActiveAuthentication::humanReadable(const std::vector<uint8_t> &data)
{
    return dataFromVector(data);
}

QByteArray NFCActiveAuthentication::dataFromVector(const std::vector<uint8_t> &data)
{
    QByteArray arr;
    for(auto it = data.begin(); it != data.end(); it++){
        arr.append(*it);
    }
    return arr;

}
