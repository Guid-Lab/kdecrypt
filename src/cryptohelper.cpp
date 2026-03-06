// SPDX-FileCopyrightText: 2026 Guid <guid@guid.pl>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "cryptohelper.h"

#include <openssl/evp.h>
#include <openssl/rand.h>

CryptoHelper::CryptoHelper() = default;

CryptoHelper::~CryptoHelper()
{
    m_key.fill('\0');
}

void CryptoHelper::setKey(const QByteArray &key)
{
    m_key.fill('\0');
    m_key = key;
}

QByteArray CryptoHelper::generateKey()
{
    QByteArray newKey(KEY_SIZE, '\0');
    if (RAND_bytes(reinterpret_cast<unsigned char *>(newKey.data()), KEY_SIZE) != 1)
        return {};
    return newKey;
}

QByteArray CryptoHelper::encrypt(const QByteArray &plaintext) const
{
    if (plaintext.isEmpty())
        return plaintext;
    if (!hasKey())
        return {};

    QByteArray iv(IV_SIZE, '\0');
    if (RAND_bytes(reinterpret_cast<unsigned char *>(iv.data()), IV_SIZE) != 1)
        return {};

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return {};

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr,
                           reinterpret_cast<const unsigned char *>(m_key.constData()),
                           reinterpret_cast<const unsigned char *>(iv.constData())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }

    QByteArray ciphertext(plaintext.size(), '\0');
    int len = 0;
    if (EVP_EncryptUpdate(ctx, reinterpret_cast<unsigned char *>(ciphertext.data()), &len,
                          reinterpret_cast<const unsigned char *>(plaintext.constData()),
                          plaintext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }

    int totalLen = len;
    if (EVP_EncryptFinal_ex(ctx, reinterpret_cast<unsigned char *>(ciphertext.data()) + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }
    totalLen += len;
    ciphertext.resize(totalLen);

    QByteArray tag(TAG_SIZE, '\0');
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE,
                            reinterpret_cast<unsigned char *>(tag.data())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }

    EVP_CIPHER_CTX_free(ctx);

    QByteArray output;
    output.reserve(IV_SIZE + TAG_SIZE + ciphertext.size());
    output.append(iv);
    output.append(tag);
    output.append(ciphertext);
    return output;
}

QByteArray CryptoHelper::decrypt(const QByteArray &ciphertext) const
{
    if (ciphertext.isEmpty())
        return ciphertext;
    if (!hasKey())
        return {};

    const int headerSize = IV_SIZE + TAG_SIZE;
    if (ciphertext.size() < headerSize)
        return {};

    const QByteArray iv = ciphertext.left(IV_SIZE);
    const QByteArray tag = ciphertext.mid(IV_SIZE, TAG_SIZE);
    const QByteArray encrypted = ciphertext.mid(headerSize);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return {};

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr,
                           reinterpret_cast<const unsigned char *>(m_key.constData()),
                           reinterpret_cast<const unsigned char *>(iv.constData())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }

    QByteArray plaintext(encrypted.size(), '\0');
    int len = 0;
    if (EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char *>(plaintext.data()), &len,
                          reinterpret_cast<const unsigned char *>(encrypted.constData()),
                          encrypted.size()) != 1) {
        plaintext.fill('\0');
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }

    int totalLen = len;

    QByteArray mutableTag(tag);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE,
                        reinterpret_cast<unsigned char *>(mutableTag.data()));

    int ret = EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char *>(plaintext.data()) + len, &len);
    EVP_CIPHER_CTX_free(ctx);

    if (ret <= 0) {
        plaintext.fill('\0');
        return {};  // auth failed
    }

    totalLen += len;
    plaintext.resize(totalLen);
    return plaintext;
}
