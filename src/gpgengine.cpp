// SPDX-FileCopyrightText: 2026 Guid <guid@guid.pl>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "gpgengine.h"

#include <KLocalizedString>

#include <QFile>
#include <QFileInfo>
#include <QProcess>
#include <QRegularExpression>
#include <QTemporaryFile>

void GpgEngine::setPassphraseProvider(PassphraseProvider provider)
{
    m_passphraseProvider = std::move(provider);
}

void GpgEngine::secureRemove(const QString &path)
{
    QFile file(path);
    if (file.open(QIODevice::ReadWrite)) {
        const qint64 size = file.size();
        const QByteArray zeros(qMin(size, qint64(65536)), '\0');
        qint64 remaining = size;
        file.seek(0);
        while (remaining > 0) {
            qint64 written = file.write(zeros.constData(), qMin(remaining, qint64(zeros.size())));
            if (written <= 0)
                break;
            remaining -= written;
        }
        file.flush();
        file.close();
    }
    QFile::remove(path);
}

void GpgEngine::parseDecryptStatus(const QString &status, Result &result)
{
    static const QRegularExpression rxDecKey(QStringLiteral("DECRYPTION_KEY ([0-9A-F]+) ([0-9A-F]+)"));
    static const QRegularExpression rxEncTo(QStringLiteral("ENC_TO ([0-9A-F]+)"));
    static const QRegularExpression rxNoSec(QStringLiteral("NO_SECKEY ([0-9A-F]+)"));

    const QStringList lines = status.split(QLatin1Char('\n'));
    for (const auto &line : lines) {
        if (line.contains(QLatin1String("DECRYPTION_KEY"))) {
            auto m = rxDecKey.match(line);
            if (m.hasMatch())
                result.keyUsed = m.captured(2).right(16);
        } else if (line.contains(QLatin1String("ENC_TO"))) {
            auto m = rxEncTo.match(line);
            if (m.hasMatch() && result.keyUsed.isEmpty())
                result.keyUsed = m.captured(1);
        } else if (line.contains(QLatin1String("NO_SECKEY"))) {
            auto m = rxNoSec.match(line);
            if (m.hasMatch())
                result.missingKeys << m.captured(1);
        }
    }

    if (!result.success && !result.missingKeys.isEmpty()) {
        QStringList parts;
        parts << i18n("Decryption failed: no matching secret key found.");
        parts << QString();
        parts << i18n("The file was encrypted for key(s):");
        for (const auto &k : result.missingKeys)
            parts << QStringLiteral("  - %1").arg(k);
        parts << QString();
        parts << i18n("Import the corresponding private key or ask the sender to encrypt for your key.");
        result.error = parts.join(QLatin1Char('\n'));
    }
}

GpgEngine::Result GpgEngine::decrypt(const QString &filePath)
{
    Result result;

    QFile input(filePath);
    if (!input.exists()) {
        result.error = i18n("File not found: %1", filePath);
        return result;
    }

    QTemporaryFile output;
    output.setAutoRemove(false);
    if (!output.open()) {
        result.error = i18n("Failed to create temporary file");
        return result;
    }
    output.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner);
    const QString outputPath = output.fileName();
    output.close();

    QProcess gpg;
    QStringList args;
    args << QStringLiteral("--batch")
         << QStringLiteral("--yes")
         << QStringLiteral("--status-fd") << QStringLiteral("2");

    if (m_passphraseProvider) {
        QString passphrase = m_passphraseProvider();
        if (!passphrase.isEmpty()) {
            args << QStringLiteral("--pinentry-mode") << QStringLiteral("loopback")
                 << QStringLiteral("--passphrase-fd") << QStringLiteral("0");
        }
        args << QStringLiteral("--output") << outputPath
             << QStringLiteral("--decrypt") << filePath;

        gpg.start(QStringLiteral("gpg"), args);
        if (!gpg.waitForStarted(5000)) {
            result.error = i18n("Failed to start gpg");
            passphrase.fill(QChar(0));
            secureRemove(outputPath);
            return result;
        }

        if (!passphrase.isEmpty()) {
            QByteArray passphraseUtf8 = passphrase.toUtf8();
            passphrase.fill(QChar(0));
            gpg.write(passphraseUtf8);
            gpg.write("\n");
            gpg.closeWriteChannel();
            passphraseUtf8.fill('\0');
        } else {
            passphrase.fill(QChar(0));
            gpg.closeWriteChannel();
        }
    } else {
        args << QStringLiteral("--output") << outputPath
             << QStringLiteral("--decrypt") << filePath;
        gpg.start(QStringLiteral("gpg"), args);
        if (!gpg.waitForStarted(5000)) {
            result.error = i18n("Failed to start gpg");
            QFile::remove(outputPath);
            return result;
        }
    }

    const qint64 fileSize = QFileInfo(filePath).size();
    const int timeoutMs = qMin(600000LL, 30000LL + (fileSize / (100LL * 1024 * 1024)) * 10000LL);
    if (!gpg.waitForFinished(static_cast<int>(timeoutMs))) {
        gpg.kill();
        gpg.waitForFinished(3000);
        result.error = i18n("GPG timed out");
        secureRemove(outputPath);
        return result;
    }

    const QString stderr = QString::fromUtf8(gpg.readAllStandardError());
    result.rawOutput = stderr;

    if (gpg.exitCode() != 0) {
        result.error = stderr;
        parseDecryptStatus(stderr, result);
        secureRemove(outputPath);
        return result;
    }

    result.success = true;
    parseDecryptStatus(stderr, result);

    QFile decrypted(outputPath);
    if (decrypted.open(QIODevice::ReadOnly)) {
        result.data = decrypted.readAll();
    } else {
        result.error = i18n("Failed to read decrypted output");
        result.success = false;
    }
    secureRemove(outputPath);

    return result;
}

GpgEngine::Result GpgEngine::encrypt(const QString &filePath,
                                      const QString &outputPath,
                                      const QStringList &recipients,
                                      const QString &signKey,
                                      bool armor)
{
    Result result;

    QFile input(filePath);
    if (!input.exists()) {
        result.error = i18n("File not found: %1", filePath);
        return result;
    }

    const qint64 fileSize = QFileInfo(filePath).size();
    const int encryptTimeout = static_cast<int>(qMin(600000LL, 30000LL + (fileSize / (100LL * 1024 * 1024)) * 10000LL));

    QStringList args;
    args << QStringLiteral("--batch")
         << QStringLiteral("--yes")
         << QStringLiteral("--quiet")
         << QStringLiteral("--trust-model") << QStringLiteral("tofu+pgp");

    if (armor)
        args << QStringLiteral("--armor");

    for (const auto &r : recipients)
        args << QStringLiteral("--recipient") << r;

    if (!signKey.isEmpty()) {
        args << QStringLiteral("--sign")
             << QStringLiteral("--local-user") << signKey;

        if (m_passphraseProvider) {
            QString passphrase = m_passphraseProvider();
            if (!passphrase.isEmpty()) {
                args << QStringLiteral("--pinentry-mode") << QStringLiteral("loopback")
                     << QStringLiteral("--passphrase-fd") << QStringLiteral("0");
            }

            args << QStringLiteral("--output") << outputPath
                 << QStringLiteral("--encrypt") << filePath;

            QProcess gpg;
            gpg.start(QStringLiteral("gpg"), args);
            if (!gpg.waitForStarted(5000)) {
                result.error = i18n("Failed to start gpg");
                passphrase.fill(QChar(0));
                return result;
            }

            if (!passphrase.isEmpty()) {
                QByteArray passphraseUtf8 = passphrase.toUtf8();
                passphrase.fill(QChar(0));
                gpg.write(passphraseUtf8);
                gpg.write("\n");
                gpg.closeWriteChannel();
                passphraseUtf8.fill('\0');
            } else {
                passphrase.fill(QChar(0));
                gpg.closeWriteChannel();
            }

            if (!gpg.waitForFinished(encryptTimeout)) {
                gpg.kill();
                gpg.waitForFinished(3000);
                result.error = i18n("GPG timed out");
                return result;
            }

            if (gpg.exitCode() != 0) {
                result.error = QString::fromUtf8(gpg.readAllStandardError());
                return result;
            }

            result.success = true;
            return result;
        }
    }

    args << QStringLiteral("--output") << outputPath
         << QStringLiteral("--encrypt") << filePath;

    QProcess gpg;
    gpg.start(QStringLiteral("gpg"), args);
    if (!gpg.waitForStarted(5000)) {
        result.error = i18n("Failed to start gpg");
        return result;
    }

    if (!gpg.waitForFinished(encryptTimeout)) {
        gpg.kill();
        gpg.waitForFinished(3000);
        result.error = i18n("GPG timed out");
        return result;
    }

    if (gpg.exitCode() != 0) {
        result.error = QString::fromUtf8(gpg.readAllStandardError());
        return result;
    }

    result.success = true;
    return result;
}
