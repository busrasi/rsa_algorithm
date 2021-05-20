#include "rsa_manager.h"

#include <exception>
#include <iostream>
#include <optional>
#include <stdio.h>

#include <QDebug>
#include <QFile>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

//Data from icao p11 active authentication example
constexpr auto const messageToEncrypt = "6A9D2784A67F8E7C659973EA1AEA25D95B6C8F91E5002F369F0FBDCE8A3CEC1991B543F1696546C5524CF23A5303CD6C98599F40B79F377B5F3A1406B3B4D8F96784D23AA88DB7E1032A405E69325FA91A6E86F5C71AEA978264C4A207446DAD4E7292E2DCDA3024B47DA8C063AA1E6D22FBD976AB0FE73D94D2D9C6D88127BC";

RSAManager::RSAManager()
{
    const auto rawData = toVector(dataFromString(messageToEncrypt));
    std::vector<uint8_t> decryptedData{};
    m_encryptedTestMessage.resize(rawData.size());
    m_decryptedMessage.resize(rawData.size());


    m_e = BN_new();
    m_rc = BN_set_word(m_e, RSA_F4);
    m_rsaKeyPair = RSA_new();
    m_rc = RSA_generate_key_ex(m_rsaKeyPair, 2048, m_e, NULL);
    m_privateRSAKey=  RSAPrivateKey_dup(m_rsaKeyPair);
    m_publicRSAKey = RSAPublicKey_dup(m_rsaKeyPair);

    auto encResult = RSA_private_encrypt(rawData.size(), rawData.data(), m_encryptedTestMessage.data(), m_privateRSAKey, RSA_PKCS1_PADDING);
    auto decResult = RSA_public_decrypt(RSA_size(m_publicRSAKey),m_encryptedTestMessage.data() ,m_decryptedMessage.data(), m_publicRSAKey, RSA_PKCS1_PADDING);

    qDebug() << __LINE__ << __PRETTY_FUNCTION__ << "raw msg: " << humanReadable(dataFromVector(rawData));
    qDebug() << __LINE__ << __PRETTY_FUNCTION__ << "enc msg: " << humanReadable(dataFromVector(m_encryptedTestMessage));
    qDebug() << __LINE__ << __PRETTY_FUNCTION__ << "dec msg: " << humanReadable(dataFromVector(m_decryptedMessage));
}

RSAManager::~RSAManager()
{


}

std::vector<uint8_t> RSAManager::toVector(const QByteArray &data)
{
    std::vector<uint8_t> vec{};
    for(auto it = data.begin(); it != data.end(); it++){
        vec.push_back(*it);
    }
    return vec;
}

QByteArray RSAManager::dataFromString(const QString &data)
{
    return QByteArray::fromHex(data.toUpper().toLatin1());
}

QString RSAManager::humanReadable(const QByteArray &data)
{
    return data.toHex().toUpper();
}

QString RSAManager::humanReadable(const std::vector<uint8_t> &data)
{
    return dataFromVector(data);
}

QByteArray RSAManager::dataFromVector(const std::vector<uint8_t> &data)
{
    QByteArray arr;
    for(auto it = data.begin(); it != data.end(); it++){
        arr.append(*it);
    }
    return arr;

}

std::vector<uint8_t> RSAManager::encryptedTestMessage() const
{
    return m_encryptedTestMessage;
}

rsa_st *RSAManager::publicRSAKey() const
{
    return m_publicRSAKey;
}
