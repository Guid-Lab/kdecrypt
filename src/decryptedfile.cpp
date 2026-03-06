// SPDX-FileCopyrightText: 2026 Guid <guid@guid.pl>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "decryptedfile.h"

QString DecryptedFile::sizeString() const
{
    const qint64 size = dataSize;
    if (size < 1024)
        return QString::number(size) + QStringLiteral(" B");
    if (size < 1024 * 1024)
        return QString::number(size / 1024.0, 'f', 1) + QStringLiteral(" KiB");
    if (size < 1024LL * 1024 * 1024)
        return QString::number(size / (1024.0 * 1024.0), 'f', 1) + QStringLiteral(" MiB");
    return QString::number(size / (1024.0 * 1024.0 * 1024.0), 'f', 2) + QStringLiteral(" GiB");
}
