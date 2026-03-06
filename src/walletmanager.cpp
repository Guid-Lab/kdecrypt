// SPDX-FileCopyrightText: 2026 Guid <guid@guid.pl>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "walletmanager.h"

WalletManager::WalletManager() = default;
WalletManager::~WalletManager() = default;

bool WalletManager::open(WId windowId)
{
    m_wallet.reset(KWallet::Wallet::openWallet(
        KWallet::Wallet::LocalWallet(), windowId));

    if (!m_wallet)
        return false;

    if (!m_wallet->hasFolder(QLatin1String(FOLDER)))
        m_wallet->createFolder(QLatin1String(FOLDER));

    m_wallet->setFolder(QLatin1String(FOLDER));
    return true;
}

bool WalletManager::storePassphrase(const QString &keyId, const QString &passphrase)
{
    if (!m_wallet)
        return false;
    return m_wallet->writePassword(keyId, passphrase) == 0;
}

QString WalletManager::retrievePassphrase(const QString &keyId)
{
    if (!m_wallet)
        return {};

    QString passphrase;
    if (m_wallet->readPassword(keyId, passphrase) == 0)
        return passphrase;
    return {};
}

bool WalletManager::hasPassphrase(const QString &keyId) const
{
    if (!m_wallet)
        return false;
    return m_wallet->hasEntry(keyId);
}

void WalletManager::removePassphrase(const QString &keyId)
{
    if (m_wallet)
        m_wallet->removeEntry(keyId);
}
