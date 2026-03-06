// SPDX-FileCopyrightText: 2026 Guid <guid@guid.pl>
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <QString>
#include <KWallet>
#include <memory>

class WalletManager
{
public:
    WalletManager();
    ~WalletManager();

    bool open(WId windowId);
    bool storePassphrase(const QString &keyId, const QString &passphrase);
    QString retrievePassphrase(const QString &keyId);
    bool hasPassphrase(const QString &keyId) const;
    void removePassphrase(const QString &keyId);

private:
    static constexpr const char *FOLDER = "kdecrypt";
    std::unique_ptr<KWallet::Wallet> m_wallet;
};
