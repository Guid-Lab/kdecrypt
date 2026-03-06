// SPDX-FileCopyrightText: 2026 Guid <guid@guid.pl>
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <QString>
#include <QByteArray>
#include <QDateTime>

struct DecryptedFile {
    QString sourcePath;
    QString originalName;
    QByteArray data;          // encrypted with CryptoHelper
    qint64 dataSize = 0;     // original plaintext size
    QDateTime decryptedAt;
    QString decryptedWithKey;

    QString sizeString() const;
};
