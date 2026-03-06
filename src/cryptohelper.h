// SPDX-FileCopyrightText: 2026 Guid <guid@guid.pl>
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <QByteArray>

class CryptoHelper
{
public:
    CryptoHelper();
    ~CryptoHelper();
    CryptoHelper(const CryptoHelper &) = delete;
    CryptoHelper &operator=(const CryptoHelper &) = delete;

    void setKey(const QByteArray &key);
    bool hasKey() const { return m_key.size() == KEY_SIZE; }

    static QByteArray generateKey();
    QByteArray encrypt(const QByteArray &plaintext) const;
    QByteArray decrypt(const QByteArray &ciphertext) const;

    static constexpr int KEY_SIZE = 32;  // AES-256
    static constexpr int IV_SIZE = 12;   // GCM nonce
    static constexpr int TAG_SIZE = 16;  // GCM auth tag

private:
    QByteArray m_key;
};
