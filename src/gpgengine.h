// SPDX-FileCopyrightText: 2026 Guid <guid@guid.pl>
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <QByteArray>
#include <QString>
#include <QStringList>
#include <functional>

class GpgEngine
{
public:
    struct Result {
        bool success = false;
        QByteArray data;
        QString error;
        QString rawOutput;
        QString keyUsed;
        QStringList missingKeys;
    };

    using PassphraseProvider = std::function<QString()>;

    GpgEngine() = default;
    GpgEngine(const GpgEngine &) = delete;
    GpgEngine &operator=(const GpgEngine &) = delete;

    void setPassphraseProvider(PassphraseProvider provider);
    Result decrypt(const QString &filePath);
    Result encrypt(const QString &filePath, const QString &outputPath,
                   const QStringList &recipients,
                   const QString &signKey = {}, bool armor = false);
    static void secureRemove(const QString &path);

private:
    static void parseDecryptStatus(const QString &status, Result &result);
    PassphraseProvider m_passphraseProvider;
};
