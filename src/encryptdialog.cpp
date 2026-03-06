// SPDX-FileCopyrightText: 2026 Guid <guid@guid.pl>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "encryptdialog.h"

#include <KLocalizedString>

#include <QCheckBox>
#include <QComboBox>
#include <QDialogButtonBox>
#include <QGroupBox>
#include <QHeaderView>
#include <QLabel>
#include <QMessageBox>
#include <QProcess>
#include <QPushButton>
#include <QTreeWidget>
#include <QVBoxLayout>

EncryptDialog::EncryptDialog(QWidget *parent)
    : QDialog(parent)
{
    setWindowTitle(i18n("Encrypt File"));
    setMinimumSize(600, 450);

    auto *layout = new QVBoxLayout(this);

    auto *recipientGroup = new QGroupBox(i18n("Recipients (public keys)"), this);
    auto *recipientLayout = new QVBoxLayout(recipientGroup);

    auto *hint = new QLabel(i18n("Select one or more recipients who will be able to decrypt the file:"), this);
    hint->setWordWrap(true);
    recipientLayout->addWidget(hint);

    m_recipientList = new QTreeWidget(this);
    m_recipientList->setHeaderLabels({i18n("User ID"), i18n("Key ID"), i18n("Type")});
    m_recipientList->setRootIsDecorated(false);
    m_recipientList->setAlternatingRowColors(true);
    m_recipientList->setSelectionMode(QAbstractItemView::NoSelection);
    m_recipientList->header()->setStretchLastSection(true);
    m_recipientList->setAccessibleName(i18n("Recipient keys"));
    recipientLayout->addWidget(m_recipientList);

    layout->addWidget(recipientGroup);

    auto *ownKeyGroup = new QGroupBox(i18n("Your Key"), this);
    auto *ownKeyLayout = new QVBoxLayout(ownKeyGroup);

    auto *ownKeyHint = new QLabel(i18n("Select your key to encrypt the file for yourself as well. "
                                        "Without this, you will not be able to decrypt the file later."), this);
    ownKeyHint->setWordWrap(true);
    ownKeyLayout->addWidget(ownKeyHint);

    auto *ownKeyForm = new QHBoxLayout();
    ownKeyForm->addWidget(new QLabel(i18n("My key:"), this));
    m_ownKeyCombo = new QComboBox(this);
    m_ownKeyCombo->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    m_ownKeyCombo->setAccessibleName(i18n("Your encryption key"));
    ownKeyForm->addWidget(m_ownKeyCombo);
    ownKeyLayout->addLayout(ownKeyForm);

    m_signCheck = new QCheckBox(i18n("Also sign with this key (proves you sent the file)"), this);
    m_signCheck->setChecked(true);
    ownKeyLayout->addWidget(m_signCheck);

    layout->addWidget(ownKeyGroup);

    m_armorCheck = new QCheckBox(i18n("ASCII armor output (.asc)"), this);
    m_armorCheck->setChecked(false);
    m_armorCheck->setAccessibleDescription(i18n("Output the encrypted file as ASCII text instead of binary. Useful for email."));
    layout->addWidget(m_armorCheck);

    auto *buttons = new QDialogButtonBox(
        QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
    buttons->button(QDialogButtonBox::Ok)->setText(i18n("Encrypt"));
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    connect(buttons, &QDialogButtonBox::accepted, this, [this]() {
        if (selectedRecipients().isEmpty()) {
            QMessageBox::warning(this, i18n("Error"), i18n("Select at least one recipient."));
            return;
        }
        bool hasExternalRecipient = false;
        for (int i = 0; i < m_recipientList->topLevelItemCount(); ++i) {
            if (m_recipientList->topLevelItem(i)->checkState(0) == Qt::Checked) {
                hasExternalRecipient = true;
                break;
            }
        }
        if (!hasExternalRecipient && !ownKey().isEmpty()) {
            auto answer = QMessageBox::question(
                this, i18n("No External Recipients"),
                i18n("No external recipients selected. The file will only be decryptable by you.\n\nContinue?"));
            if (answer != QMessageBox::Yes)
                return;
        }
        accept();
    });
    layout->addWidget(buttons);

    loadPublicKeys();
    loadSecretKeys();

    if (m_ownKeyCombo->count() > 1)
        m_ownKeyCombo->setCurrentIndex(1);
}

void EncryptDialog::loadPublicKeys()
{
    m_recipientList->clear();

    QProcess gpg;
    gpg.start(QStringLiteral("gpg"),
              {QStringLiteral("--list-keys"),
               QStringLiteral("--with-colons"),
               QStringLiteral("--batch")});

    if (!gpg.waitForFinished(5000)) {
        gpg.kill();
        gpg.waitForFinished(3000);
        return;
    }

    const QString output = QString::fromUtf8(gpg.readAllStandardOutput());
    const QStringList lines = output.split(QLatin1Char('\n'));

    QString currentFpr;
    QString currentType;
    QString currentValidity;

    for (const auto &line : lines) {
        const QStringList fields = line.split(QLatin1Char(':'));
        if (fields.size() < 10)
            continue;

        if (fields[0] == QLatin1String("pub")) {
            currentValidity = fields[1];
            currentType = fields[3];
            if (currentType == QLatin1String("1") || currentType == QLatin1String("2") || currentType == QLatin1String("3"))
                currentType = QStringLiteral("RSA %1").arg(fields[2]);
            else if (currentType == QLatin1String("22"))
                currentType = QStringLiteral("EdDSA");
            else if (currentType == QLatin1String("18"))
                currentType = QStringLiteral("ECDH");
            else if (currentType == QLatin1String("19"))
                currentType = QStringLiteral("ECDSA %1").arg(fields[2]);
            else
                currentType += QStringLiteral(" %1").arg(fields[2]);
        } else if (fields[0] == QLatin1String("fpr")) {
            currentFpr = fields[9];
        } else if (fields[0] == QLatin1String("uid") && !currentFpr.isEmpty()) {
            if (currentValidity == QLatin1String("e") ||
                currentValidity == QLatin1String("r") ||
                currentValidity == QLatin1String("d") ||
                currentValidity == QLatin1String("i")) {
                currentFpr.clear();
                continue;
            }
            auto *item = new QTreeWidgetItem(m_recipientList);
            item->setText(0, fields[9]);
            item->setText(1, currentFpr.right(16));
            item->setText(2, currentType);
            item->setData(0, Qt::UserRole, currentFpr);
            item->setCheckState(0, Qt::Unchecked);
            currentFpr.clear();
        }
    }

    for (int i = 0; i < m_recipientList->columnCount(); ++i)
        m_recipientList->resizeColumnToContents(i);
}

void EncryptDialog::loadSecretKeys()
{
    m_ownKeyCombo->clear();
    m_ownKeyCombo->addItem(i18n("(none — won't be able to decrypt)"), QString());

    QProcess gpg;
    gpg.start(QStringLiteral("gpg"),
              {QStringLiteral("--list-secret-keys"),
               QStringLiteral("--with-colons"),
               QStringLiteral("--batch")});

    if (!gpg.waitForFinished(5000)) {
        gpg.kill();
        gpg.waitForFinished(3000);
        return;
    }

    const QString output = QString::fromUtf8(gpg.readAllStandardOutput());
    const QStringList lines = output.split(QLatin1Char('\n'));

    QString currentFpr;
    QString currentValidity;
    bool afterSec = false;
    for (const auto &line : lines) {
        const QStringList fields = line.split(QLatin1Char(':'));
        if (fields.size() < 10)
            continue;

        if (fields[0] == QLatin1String("sec")) {
            afterSec = true;
            currentFpr.clear();
            currentValidity = fields[1];
        } else if (fields[0] == QLatin1String("ssb")) {
            afterSec = false;
        } else if (fields[0] == QLatin1String("fpr") && afterSec && currentFpr.isEmpty()) {
            currentFpr = fields[9];
        } else if (fields[0] == QLatin1String("uid") && !currentFpr.isEmpty()) {
            if (currentValidity == QLatin1String("e") ||
                currentValidity == QLatin1String("r") ||
                currentValidity == QLatin1String("d") ||
                currentValidity == QLatin1String("i")) {
                currentFpr.clear();
                continue;
            }
            const QString label = fields[9] + QStringLiteral("  [") + currentFpr.right(8) + QStringLiteral("]");
            m_ownKeyCombo->addItem(label, currentFpr);
            currentFpr.clear();
            afterSec = false;
        }
    }
}

QStringList EncryptDialog::selectedRecipients() const
{
    QStringList recipients;

    const QString own = ownKey();
    if (!own.isEmpty())
        recipients << own;

    for (int i = 0; i < m_recipientList->topLevelItemCount(); ++i) {
        auto *item = m_recipientList->topLevelItem(i);
        if (item->checkState(0) == Qt::Checked) {
            const QString fpr = item->data(0, Qt::UserRole).toString();
            if (fpr != own)
                recipients << fpr;
        }
    }
    return recipients;
}

QString EncryptDialog::ownKey() const
{
    return m_ownKeyCombo->currentData().toString();
}

QString EncryptDialog::signingKey() const
{
    if (m_signCheck->isChecked())
        return ownKey();
    return {};
}

bool EncryptDialog::armorOutput() const
{
    return m_armorCheck->isChecked();
}
