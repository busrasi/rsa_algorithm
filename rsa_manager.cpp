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
constexpr auto const messageToEncrypt = "756B683B036A6368F4A2EB29EA700F96E26100AFC0809F60A91733BA29CAB3628CB1A017190A85DADE83F0B977BB513FC9C672E5C93EFEBBE250FE1B722C7CEEF35D26FC8F19219C92D362758FA8CB0FF68CEF320A8753913ED25F69F7CEE7726923B2C43437800BBC9BC028C49806CF2E47D16AE2B2CC1678F2A4456EF98FC9";

RSAManager::RSAManager()
{
    const auto rawData = toVector(dataFromString(messageToEncrypt));
    std::vector<uint8_t> decryptedData{};
    m_encryptedTestMessage.resize(rawData.size());
    decryptedData.resize(rawData.size());


    m_e = BN_new();
    m_rc = BN_set_word(m_e, RSA_F4);
    m_rsaKeyPair = RSA_new();
    m_rc = RSA_generate_key_ex(m_rsaKeyPair, 2048, m_e, NULL);
    m_privateRSAKey=  RSAPrivateKey_dup(m_rsaKeyPair);
    m_publicRSAKey = RSAPublicKey_dup(m_rsaKeyPair);

    auto encResult = RSA_private_encrypt(rawData.size(), rawData.data(), m_encryptedTestMessage.data(), m_privateRSAKey, RSA_PKCS1_PADDING);
    auto decResult = RSA_public_decrypt(RSA_size(m_publicRSAKey),m_encryptedTestMessage.data() ,decryptedData.data(), m_publicRSAKey, RSA_PKCS1_PADDING);

    qDebug() << __LINE__ << __PRETTY_FUNCTION__ << "raw msg: " << humanReadable(dataFromVector(rawData));
    qDebug() << __LINE__ << __PRETTY_FUNCTION__ << "enc msg: " << humanReadable(dataFromVector(m_encryptedTestMessage));
    qDebug() << __LINE__ << __PRETTY_FUNCTION__ << "dec msg: " << humanReadable(dataFromVector(decryptedData));
//    qDebug() << m_publicRSAKey;

    qDebug() << __LINE__ << __PRETTY_FUNCTION__ << "m_publicRSAKey: " << m_publicRSAKey;

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
