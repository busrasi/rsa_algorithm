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
#include <cassert>
#define ASSERT assert

//Data from icao p11 active authentication example
constexpr auto const messageToEncrypt = "756B683B036A6368F4A2EB29EA700F96E26100AFC0809F60A91733BA29CAB3628CB1A017190A85DADE83F0B977BB513FC9C672E5C93EFEBBE250FE1B722C7CEEF35D26FC8F19219C92D362758FA8CB0FF68CEF320A8753913ED25F69F7CEE7726923B2C43437800BBC9BC028C49806CF2E47D16AE2B2CC1678F2A4456EF98FC9";

using namespace std;

RSAManager::RSAManager()
{
    qDebug() << __LINE__ << __PRETTY_FUNCTION__;
    const auto rawData = toVector(dataFromString(messageToEncrypt));
    std::vector<uint8_t> decryptedData{};
    m_encryptedTestMessage.resize(rawData.size());
    decryptedData.resize(rawData.size());

    qDebug() << __LINE__ << __PRETTY_FUNCTION__;

    int rc;
    BIGNUM *e = BN_new();
    rc = BN_set_word(e, RSA_F4);
    assert(rc==1);
    RSA *rsaKeyPair = RSA_new();
    rc = RSA_generate_key_ex(rsaKeyPair, 2048, e, NULL);
    ASSERT(rc ==1);
    m_privateRSAKey = RSA_new();
    m_privateRSAKey=  RSAPrivateKey_dup(rsaKeyPair);
    m_publicRSAKey = RSA_new();
    m_publicRSAKey = RSAPublicKey_dup(rsaKeyPair);

    qDebug() << __LINE__ << __PRETTY_FUNCTION__;

    auto encResult = RSA_private_encrypt(rawData.size(), rawData.data(), m_encryptedTestMessage.data(), m_privateRSAKey, RSA_PKCS1_PADDING);
    auto decResult = RSA_public_decrypt(RSA_size(m_publicRSAKey),m_encryptedTestMessage.data() ,decryptedData.data(), m_publicRSAKey, RSA_PKCS1_PADDING);


    qDebug() << "RSA Size: " << RSA_size(m_publicRSAKey);
    qDebug() << "encResult:" << encResult << "decResult:" << decResult;
    qDebug() << __LINE__ << __PRETTY_FUNCTION__ << "raw data: " << humanReadable(dataFromVector(rawData));
    qDebug() << __LINE__ << __PRETTY_FUNCTION__ << "encry data: " << humanReadable(dataFromVector(m_encryptedTestMessage));
    qDebug() << __LINE__ << __PRETTY_FUNCTION__ << "decry data: " << humanReadable(dataFromVector(decryptedData));




}

RSAManager::~RSAManager()
{


}

std::vector<uint8_t> RSAManager::publicKey()
{
    std::vector<uint8_t> publicKey{};
    publicKey.resize(RSA_size(m_publicRSAKey));
    auto publicKeyPtr = publicKey.data();
    auto res = i2d_RSA_PUBKEY(m_publicRSAKey, &publicKeyPtr);
    qDebug() << "pub key res: " << res;
    qDebug() << __LINE__ << __PRETTY_FUNCTION__ << "publicKey data: " << humanReadable(dataFromVector(publicKey));
    return publicKey;
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

/*
//Read RSA Key Pair PEM
auto privateFilePointer = fopen("/Users/muhammet/Training/rsa_algorithm/resources/rsa.private", "rb");
auto publicFilePointer = fopen("/Users/muhammet/Training/rsa_algorithm/resources/rsa.public", "rb");

qDebug() << __LINE__ << __PRETTY_FUNCTION__ << "privateFilePointer:" << privateFilePointer;
qDebug() << __LINE__ << __PRETTY_FUNCTION__ << "publicFilePointer:" << publicFilePointer;

RSA *privateRSA{nullptr};
RSA *publicRSA{nullptr};

PEM_read_RSAPrivateKey(privateFilePointer, &privateRSA, nullptr, nullptr);
PEM_read_RSA_PUBKEY(publicFilePointer, &publicRSA, nullptr, nullptr);
qDebug() << __LINE__ << __PRETTY_FUNCTION__ << "privateRSA:" << privateRSA;
qDebug() << __LINE__ << __PRETTY_FUNCTION__ << "publicRSA:" << publicRSA;

//Start Encryption with Private RSA Key
const auto rawData = toVector(dataFromString(messageToEncrypt));
std::vector<uint8_t> encryptedData{};
encryptedData.resize(rawData.size());
//https://www.openssl.org/docs/man1.1.1/man3/RSA_private_encrypt.html
const auto encryptResult = RSA_private_encrypt(rawData.size(), rawData.data(), encryptedData.data(), privateRSA, RSA_PKCS1_PADDING);
qDebug() << __LINE__ << __PRETTY_FUNCTION__ << "encryption result: " << encryptResult;
qDebug() << __LINE__ << __PRETTY_FUNCTION__ << "rawData: " << humanReadable(dataFromVector(rawData));
qDebug() << __LINE__ << __PRETTY_FUNCTION__ << "encryption result: " << humanReadable(dataFromVector(encryptedData));

//Start Decryption with Public RSA Key
std::vector<uint8_t> decryptedData{};
decryptedData.resize(encryptedData.size());
const auto decrpytResult = RSA_public_decrypt(RSA_size(publicRSA), encryptedData.data(), decryptedData.data(), publicRSA, RSA_PKCS1_PADDING);
qDebug() << __LINE__ << __PRETTY_FUNCTION__ << "decrpytResult result: " << decrpytResult;
qDebug() << __LINE__ << __PRETTY_FUNCTION__ << "decryption data result: " << humanReadable(dataFromVector(decryptedData));
*/
