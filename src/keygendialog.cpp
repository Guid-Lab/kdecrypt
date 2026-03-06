// SPDX-FileCopyrightText: 2026 Guid <guid@guid.pl>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "keygendialog.h"

#include <KLocalizedString>

#include <QCheckBox>
#include <QComboBox>
#include <QDateEdit>
#include <QDialogButtonBox>
#include <QPushButton>
#include <QFormLayout>
#include <QGroupBox>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QVBoxLayout>

KeyGenDialog::KeyGenDialog(QWidget *parent)
    : QDialog(parent)
{
    setWindowTitle(i18n("Generate GPG Key"));
    setMinimumWidth(520);

    auto *layout = new QVBoxLayout(this);

    auto *identityGroup = new QGroupBox(i18n("Identity"), this);
    auto *identityForm = new QFormLayout(identityGroup);

    m_nameEdit = new QLineEdit(this);
    m_nameEdit->setPlaceholderText(i18n("e.g. Jan Kowalski"));
    m_nameEdit->setAccessibleName(i18n("Name"));
    identityForm->addRow(i18n("Name:"), m_nameEdit);

    m_emailEdit = new QLineEdit(this);
    m_emailEdit->setPlaceholderText(i18n("e.g. jan@example.com"));
    m_emailEdit->setAccessibleName(i18n("Email"));
    identityForm->addRow(i18n("Email:"), m_emailEdit);

    m_commentEdit = new QLineEdit(this);
    m_commentEdit->setPlaceholderText(i18n("e.g. Work key, Personal"));
    m_commentEdit->setAccessibleName(i18n("Comment"));
    identityForm->addRow(i18n("Comment:"), m_commentEdit);

    layout->addWidget(identityGroup);

    auto *keyGroup = new QGroupBox(i18n("Key Parameters"), this);
    auto *keyForm = new QFormLayout(keyGroup);

    m_keyTypeCombo = new QComboBox(this);
    m_keyTypeCombo->setAccessibleName(i18n("Key type"));
    m_keyTypeCombo->addItem(QStringLiteral("EdDSA (Ed25519)"), QStringLiteral("eddsa"));
    m_keyTypeCombo->addItem(QStringLiteral("RSA"), QStringLiteral("rsa"));
    m_keyTypeCombo->addItem(QStringLiteral("ECDSA (NIST P-256)"), QStringLiteral("ecdsa-p256"));
    m_keyTypeCombo->addItem(QStringLiteral("ECDSA (NIST P-384)"), QStringLiteral("ecdsa-p384"));
    m_keyTypeCombo->addItem(QStringLiteral("ECDSA (NIST P-521)"), QStringLiteral("ecdsa-p521"));
    m_keyTypeCombo->addItem(QStringLiteral("DSA (legacy)"), QStringLiteral("dsa"));
    keyForm->addRow(i18n("Key type:"), m_keyTypeCombo);

    m_keySizeCombo = new QComboBox(this);
    m_keySizeCombo->setAccessibleName(i18n("Key size"));
    keyForm->addRow(i18n("Key size:"), m_keySizeCombo);

    m_subkeyTypeCombo = new QComboBox(this);
    m_subkeyTypeCombo->setAccessibleName(i18n("Subkey type"));
    m_subkeyTypeCombo->addItem(QStringLiteral("ECDH (Curve25519)"), QStringLiteral("ecdh-cv25519"));
    m_subkeyTypeCombo->addItem(QStringLiteral("RSA"), QStringLiteral("rsa"));
    m_subkeyTypeCombo->addItem(QStringLiteral("ECDH (NIST P-256)"), QStringLiteral("ecdh-p256"));
    m_subkeyTypeCombo->addItem(QStringLiteral("ECDH (NIST P-384)"), QStringLiteral("ecdh-p384"));
    m_subkeyTypeCombo->addItem(QStringLiteral("ECDH (NIST P-521)"), QStringLiteral("ecdh-p521"));
    m_subkeyTypeCombo->addItem(QStringLiteral("ElGamal (legacy)"), QStringLiteral("elg"));
    m_subkeyTypeCombo->addItem(i18n("None (signing only)"), QStringLiteral("none"));
    keyForm->addRow(i18n("Subkey type:"), m_subkeyTypeCombo);

    m_subkeySizeCombo = new QComboBox(this);
    m_subkeySizeCombo->setAccessibleName(i18n("Subkey size"));
    keyForm->addRow(i18n("Subkey size:"), m_subkeySizeCombo);

    layout->addWidget(keyGroup);

    auto *expiryGroup = new QGroupBox(i18n("Expiration"), this);
    auto *expiryForm = new QFormLayout(expiryGroup);

    m_noExpiryCheck = new QCheckBox(i18n("No expiration"), this);
    m_noExpiryCheck->setAccessibleName(i18n("No expiration"));
    m_noExpiryCheck->setChecked(true);
    expiryForm->addRow(QString(), m_noExpiryCheck);

    m_expiryDate = new QDateEdit(this);
    m_expiryDate->setAccessibleName(i18n("Expiration date"));
    m_expiryDate->setCalendarPopup(true);
    m_expiryDate->setMinimumDate(QDate::currentDate().addDays(1));
    m_expiryDate->setDate(QDate::currentDate().addYears(2));
    m_expiryDate->setEnabled(false);
    expiryForm->addRow(i18n("Expires:"), m_expiryDate);

    layout->addWidget(expiryGroup);

    auto *passGroup = new QGroupBox(i18n("Passphrase"), this);
    auto *passForm = new QFormLayout(passGroup);

    m_passphraseEdit = new QLineEdit(this);
    m_passphraseEdit->setEchoMode(QLineEdit::Password);
    m_passphraseEdit->setPlaceholderText(i18n("Leave empty for no passphrase"));
    m_passphraseEdit->setAccessibleName(i18n("Passphrase"));
    m_passphraseEdit->setAccessibleDescription(i18n("Leave empty to create a key without passphrase protection"));
    passForm->addRow(i18n("Passphrase:"), m_passphraseEdit);

    m_passphraseConfirmEdit = new QLineEdit(this);
    m_passphraseConfirmEdit->setEchoMode(QLineEdit::Password);
    m_passphraseConfirmEdit->setAccessibleName(i18n("Confirm passphrase"));
    passForm->addRow(i18n("Confirm:"), m_passphraseConfirmEdit);

    layout->addWidget(passGroup);

    auto *buttons = new QDialogButtonBox(
        QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
    buttons->button(QDialogButtonBox::Ok)->setText(i18n("Generate"));
    layout->addWidget(buttons);

    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    connect(buttons, &QDialogButtonBox::accepted, this, [this]() {
        if (m_nameEdit->text().trimmed().isEmpty()) {
            QMessageBox::warning(this, i18n("Error"), i18n("Name is required."));
            return;
        }
        if (m_emailEdit->text().trimmed().isEmpty()) {
            QMessageBox::warning(this, i18n("Error"), i18n("Email is required."));
            return;
        }
        if (!m_emailEdit->text().trimmed().contains(QLatin1Char('@'))) {
            QMessageBox::warning(this, i18n("Error"), i18n("Please enter a valid email address."));
            return;
        }
        if (m_passphraseEdit->text() != m_passphraseConfirmEdit->text()) {
            QMessageBox::warning(this, i18n("Error"), i18n("Passphrases do not match."));
            return;
        }
        m_passphraseConfirmEdit->clear();
        accept();
    });

    connect(m_keyTypeCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &KeyGenDialog::onKeyTypeChanged);
    connect(m_subkeyTypeCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &KeyGenDialog::onSubkeyTypeChanged);
    connect(m_noExpiryCheck, &QCheckBox::toggled, this, &KeyGenDialog::onNoExpiryToggled);

    onKeyTypeChanged();
    onSubkeyTypeChanged();
}

void KeyGenDialog::populateKeySizes(QComboBox *combo, const QString &type)
{
    combo->clear();
    if (type == QLatin1String("rsa")) {
        combo->addItem(QStringLiteral("2048 bits"), 2048);
        combo->addItem(QStringLiteral("3072 bits"), 3072);
        combo->addItem(QStringLiteral("4096 bits (recommended)"), 4096);
        combo->addItem(QStringLiteral("8192 bits"), 8192);
        combo->setCurrentIndex(2);
        combo->setEnabled(true);
    } else if (type == QLatin1String("dsa")) {
        combo->addItem(QStringLiteral("2048 bits"), 2048);
        combo->addItem(QStringLiteral("3072 bits (recommended)"), 3072);
        combo->setCurrentIndex(1);
        combo->setEnabled(true);
    } else if (type == QLatin1String("elg")) {
        combo->addItem(QStringLiteral("2048 bits"), 2048);
        combo->addItem(QStringLiteral("3072 bits"), 3072);
        combo->addItem(QStringLiteral("4096 bits (recommended)"), 4096);
        combo->setCurrentIndex(2);
        combo->setEnabled(true);
    } else {
        combo->addItem(i18n("Fixed by curve"), 0);
        combo->setEnabled(false);
    }
}

void KeyGenDialog::onKeyTypeChanged()
{
    const QString type = m_keyTypeCombo->currentData().toString();
    populateKeySizes(m_keySizeCombo, type);

    if (type == QLatin1String("eddsa"))
        m_subkeyTypeCombo->setCurrentIndex(0);
    else if (type == QLatin1String("rsa"))
        m_subkeyTypeCombo->setCurrentIndex(1);
    else if (type.contains(QLatin1String("p256")))
        m_subkeyTypeCombo->setCurrentIndex(2);
    else if (type.contains(QLatin1String("p384")))
        m_subkeyTypeCombo->setCurrentIndex(3);
    else if (type.contains(QLatin1String("p521")))
        m_subkeyTypeCombo->setCurrentIndex(4);
    else if (type == QLatin1String("dsa"))
        m_subkeyTypeCombo->setCurrentIndex(5);
}

void KeyGenDialog::onSubkeyTypeChanged()
{
    const QString sub = m_subkeyTypeCombo->currentData().toString();
    if (sub == QLatin1String("none")) {
        m_subkeySizeCombo->clear();
        m_subkeySizeCombo->addItem(i18n("N/A"), 0);
        m_subkeySizeCombo->setEnabled(false);
    } else {
        populateKeySizes(m_subkeySizeCombo, sub);
    }
}

void KeyGenDialog::onNoExpiryToggled(bool checked)
{
    m_expiryDate->setEnabled(!checked);
}

QString KeyGenDialog::batchConfig()
{
    QString config;
    const QString type = m_keyTypeCombo->currentData().toString();

    if (type == QLatin1String("eddsa")) {
        config += QStringLiteral("Key-Type: eddsa\nKey-Curve: ed25519\n");
    } else if (type == QLatin1String("rsa")) {
        config += QStringLiteral("Key-Type: RSA\nKey-Length: %1\n").arg(m_keySizeCombo->currentData().toInt());
    } else if (type == QLatin1String("ecdsa-p256")) {
        config += QStringLiteral("Key-Type: ecdsa\nKey-Curve: nistp256\n");
    } else if (type == QLatin1String("ecdsa-p384")) {
        config += QStringLiteral("Key-Type: ecdsa\nKey-Curve: nistp384\n");
    } else if (type == QLatin1String("ecdsa-p521")) {
        config += QStringLiteral("Key-Type: ecdsa\nKey-Curve: nistp521\n");
    } else if (type == QLatin1String("dsa")) {
        config += QStringLiteral("Key-Type: DSA\nKey-Length: %1\n").arg(m_keySizeCombo->currentData().toInt());
    }

    const QString sub = m_subkeyTypeCombo->currentData().toString();
    if (sub != QLatin1String("none")) {
        if (sub == QLatin1String("ecdh-cv25519")) {
            config += QStringLiteral("Subkey-Type: ecdh\nSubkey-Curve: cv25519\n");
        } else if (sub == QLatin1String("rsa")) {
            config += QStringLiteral("Subkey-Type: RSA\nSubkey-Length: %1\n").arg(m_subkeySizeCombo->currentData().toInt());
        } else if (sub == QLatin1String("ecdh-p256")) {
            config += QStringLiteral("Subkey-Type: ecdh\nSubkey-Curve: nistp256\n");
        } else if (sub == QLatin1String("ecdh-p384")) {
            config += QStringLiteral("Subkey-Type: ecdh\nSubkey-Curve: nistp384\n");
        } else if (sub == QLatin1String("ecdh-p521")) {
            config += QStringLiteral("Subkey-Type: ecdh\nSubkey-Curve: nistp521\n");
        } else if (sub == QLatin1String("elg")) {
            config += QStringLiteral("Subkey-Type: ELG-E\nSubkey-Length: %1\n").arg(m_subkeySizeCombo->currentData().toInt());
        }
    }

    auto sanitize = [](QString s) { return s.trimmed().remove(QLatin1Char('\n')).remove(QLatin1Char('\r')); };
    config += QStringLiteral("Name-Real: %1\n").arg(sanitize(m_nameEdit->text()));
    config += QStringLiteral("Name-Email: %1\n").arg(sanitize(m_emailEdit->text()));
    const QString comment = sanitize(m_commentEdit->text());
    if (!comment.isEmpty())
        config += QStringLiteral("Name-Comment: %1\n").arg(comment);

    if (m_noExpiryCheck->isChecked())
        config += QStringLiteral("Expire-Date: 0\n");
    else
        config += QStringLiteral("Expire-Date: %1\n").arg(m_expiryDate->date().toString(QStringLiteral("yyyy-MM-dd")));

    if (m_passphraseEdit->text().isEmpty()) {
        config += QStringLiteral("%no-protection\n");
    } else {
        config += QStringLiteral("Passphrase: %1\n").arg(m_passphraseEdit->text());
        m_passphraseEdit->clear();
    }

    config += QStringLiteral("%commit\n");
    return config;
}
