// SPDX-FileCopyrightText: 2026 Guid <guid@guid.pl>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "settingsdialog.h"
#include "keygendialog.h"

#include <KLocalizedString>

#include <QApplication>
#include <QCheckBox>
#include <QComboBox>
#include <QDialogButtonBox>
#include <QFileDialog>
#include <QFontDatabase>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QInputDialog>
#include <QLabel>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QProcess>
#include <QPushButton>
#include <QTreeWidget>
#include <QVBoxLayout>

SettingsDialog::SettingsDialog(QWidget *parent)
    : QDialog(parent)
{
    setWindowTitle(i18n("Key Manager"));
    setMinimumSize(700, 500);

    auto *layout = new QVBoxLayout(this);

    auto *keyGroup = new QGroupBox(i18n("GPG Keys"), this);
    auto *keyLayout = new QVBoxLayout(keyGroup);

    m_keyList = new QTreeWidget(this);
    m_keyList->setHeaderLabels({i18n("User ID"), i18n("Key ID"), i18n("Type"), i18n("Expires"), i18n("Created")});
    m_keyList->setRootIsDecorated(false);
    m_keyList->setAlternatingRowColors(true);
    m_keyList->setSelectionMode(QAbstractItemView::SingleSelection);
    m_keyList->header()->setStretchLastSection(true);
    m_keyList->setSortingEnabled(true);
    m_keyList->setAccessibleName(i18n("GPG secret keys"));
    keyLayout->addWidget(m_keyList);

    auto *btnRow1 = new QHBoxLayout();

    auto *importBtn = new QPushButton(QIcon::fromTheme(QStringLiteral("document-import")),
                                      i18n("Import..."), this);
    importBtn->setToolTip(i18n("Import a GPG key from a file"));
    connect(importBtn, &QPushButton::clicked, this, &SettingsDialog::onImportKey);

    m_exportBtn = new QPushButton(QIcon::fromTheme(QStringLiteral("document-export")),
                                  i18n("Export..."), this);
    m_exportBtn->setToolTip(i18n("Export the selected key to a file"));
    connect(m_exportBtn, &QPushButton::clicked, this, &SettingsDialog::onExportKey);

    auto *generateBtn = new QPushButton(QIcon::fromTheme(QStringLiteral("list-add")),
                                        i18n("Generate..."), this);
    generateBtn->setToolTip(i18n("Generate a new GPG key pair"));
    connect(generateBtn, &QPushButton::clicked, this, &SettingsDialog::onGenerateKey);

    btnRow1->addWidget(importBtn);
    btnRow1->addWidget(m_exportBtn);
    btnRow1->addWidget(generateBtn);
    btnRow1->addStretch();

    keyLayout->addLayout(btnRow1);

    auto *btnRow2 = new QHBoxLayout();

    m_detailsBtn = new QPushButton(QIcon::fromTheme(QStringLiteral("dialog-information")),
                                   i18n("Details..."), this);
    m_detailsBtn->setToolTip(i18n("Show detailed information about the selected key"));
    connect(m_detailsBtn, &QPushButton::clicked, this, &SettingsDialog::onKeyDetails);

    m_changePassBtn = new QPushButton(QIcon::fromTheme(QStringLiteral("dialog-password")),
                                      i18n("Change Passphrase..."), this);
    m_changePassBtn->setToolTip(i18n("Change the passphrase of the selected key"));
    connect(m_changePassBtn, &QPushButton::clicked, this, &SettingsDialog::onChangePassphrase);

    m_deleteBtn = new QPushButton(QIcon::fromTheme(QStringLiteral("edit-delete")),
                                  i18n("Delete"), this);
    m_deleteBtn->setToolTip(i18n("Delete the selected key permanently"));
    connect(m_deleteBtn, &QPushButton::clicked, this, &SettingsDialog::onDeleteKey);

    btnRow2->addWidget(m_detailsBtn);
    btnRow2->addWidget(m_changePassBtn);
    btnRow2->addStretch();
    btnRow2->addWidget(m_deleteBtn);

    keyLayout->addLayout(btnRow2);
    layout->addWidget(keyGroup);

    auto *defaultKeyLayout = new QHBoxLayout();
    defaultKeyLayout->addWidget(new QLabel(i18n("Default GPG key:"), this));
    m_defaultKeyCombo = new QComboBox(this);
    m_defaultKeyCombo->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    m_defaultKeyCombo->setAccessibleName(i18n("Default GPG key"));
    defaultKeyLayout->addWidget(m_defaultKeyCombo);
    layout->addLayout(defaultKeyLayout);

    m_walletCheck = new QCheckBox(i18n("Store passphrase in KDE Wallet"), this);
    m_walletCheck->setChecked(true);
    m_walletCheck->setAccessibleDescription(i18n("When enabled, GPG passphrases are stored securely in KDE Wallet so you don't need to re-enter them"));
    layout->addWidget(m_walletCheck);

    m_rememberCheck = new QCheckBox(i18n("Remember encrypted files between sessions (re-decrypt on start)"), this);
    m_rememberCheck->setChecked(true);
    m_rememberCheck->setAccessibleDescription(i18n("When enabled, file paths are saved and automatically re-decrypted when the application starts"));
    layout->addWidget(m_rememberCheck);

    auto *buttons = new QDialogButtonBox(
        QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
    connect(buttons, &QDialogButtonBox::accepted, this, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    layout->addWidget(buttons);

    connect(m_keyList, &QTreeWidget::itemSelectionChanged,
            this, &SettingsDialog::onSelectionChanged);
    connect(m_keyList, &QTreeWidget::itemDoubleClicked,
            this, &SettingsDialog::onKeyDetails);

    loadGpgKeys();
    populateDefaultKeyCombo();
    onSelectionChanged();
}

void SettingsDialog::loadGpgKeys()
{
    m_keyList->clear();

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
    QString currentType;
    QString currentCreated;
    QString currentExpiry;
    bool afterSec = false;

    for (const auto &line : lines) {
        const QStringList fields = line.split(QLatin1Char(':'));
        if (fields.size() < 10)
            continue;

        if (fields[0] == QLatin1String("sec")) {
            afterSec = true;
            currentFpr.clear();
            currentType = fields[3]; // algo number
            if (currentType == QLatin1String("1") || currentType == QLatin1String("2") || currentType == QLatin1String("3"))
                currentType = QStringLiteral("RSA");
            else if (currentType == QLatin1String("16") || currentType == QLatin1String("20"))
                currentType = QStringLiteral("ELG");
            else if (currentType == QLatin1String("17"))
                currentType = QStringLiteral("DSA");
            else if (currentType == QLatin1String("18"))
                currentType = QStringLiteral("ECDH");
            else if (currentType == QLatin1String("19"))
                currentType = QStringLiteral("ECDSA");
            else if (currentType == QLatin1String("22"))
                currentType = QStringLiteral("EdDSA");

            if (!fields[2].isEmpty() && fields[2] != QLatin1String("0"))
                currentType += QStringLiteral(" %1").arg(fields[2]);

            bool ok;
            qint64 ts = fields[5].toLongLong(&ok);
            currentCreated = ok
                ? QDateTime::fromSecsSinceEpoch(ts).toString(QStringLiteral("yyyy-MM-dd"))
                : fields[5];

            if (!fields[6].isEmpty()) {
                qint64 exp = fields[6].toLongLong(&ok);
                if (ok && exp > 0) {
                    QDateTime expDt = QDateTime::fromSecsSinceEpoch(exp);
                    currentExpiry = expDt.toString(QStringLiteral("yyyy-MM-dd"));
                    if (expDt < QDateTime::currentDateTime())
                        currentExpiry += i18n(" (expired)");
                } else {
                    currentExpiry = i18n("Never");
                }
            } else {
                currentExpiry = i18n("Never");
            }
        } else if (fields[0] == QLatin1String("ssb")) {
            afterSec = false;
        } else if (fields[0] == QLatin1String("fpr") && afterSec && currentFpr.isEmpty()) {
            currentFpr = fields[9];
        } else if (fields[0] == QLatin1String("uid") && !currentFpr.isEmpty()) {
            auto *item = new QTreeWidgetItem(m_keyList);
            item->setText(0, fields[9]);
            item->setText(1, currentFpr.right(16));
            item->setText(2, currentType);
            item->setText(3, currentExpiry);
            item->setText(4, currentCreated);
            item->setData(0, Qt::UserRole, currentFpr);
            currentFpr.clear();
        }
    }

    for (int i = 0; i < m_keyList->columnCount(); ++i)
        m_keyList->resizeColumnToContents(i);
}

void SettingsDialog::onImportKey()
{
    const QString file = QFileDialog::getOpenFileName(
        this, i18n("Import GPG Key"), QString(),
        i18n("GPG Key Files (*.asc *.gpg *.pgp *.key);;All Files (*)"));

    if (file.isEmpty())
        return;

    QProcess gpg;
    gpg.start(QStringLiteral("gpg"),
              {QStringLiteral("--batch"), QStringLiteral("--import"), file});

    if (!gpg.waitForFinished(10000)) {
        gpg.kill();
        gpg.waitForFinished(3000);
        QMessageBox::warning(this, i18n("Import Failed"), i18n("GPG timed out."));
        return;
    }

    const QString err = QString::fromUtf8(gpg.readAllStandardError());
    if (gpg.exitCode() != 0) {
        QMessageBox::warning(this, i18n("Import Failed"), err);
    } else {
        QMessageBox::information(this, i18n("Import"), i18n("Key imported successfully.\n\n%1", err));
        loadGpgKeys();
        populateDefaultKeyCombo();
    }
}

void SettingsDialog::onExportKey()
{
    auto *item = m_keyList->currentItem();
    if (!item)
        return;

    const QString fpr = item->data(0, Qt::UserRole).toString();
    const QString uid = item->text(0);

    QStringList options = {i18n("Public key"), i18n("Private key")};
    bool ok;
    QString choice = QInputDialog::getItem(
        this, i18n("Export Key"), i18n("Export type for: %1", uid),
        options, 0, false, &ok);

    if (!ok)
        return;

    bool exportSecret = (choice == options[1]);

    if (exportSecret) {
        auto warn = QMessageBox::warning(
            this, i18n("Security Warning"),
            i18n("Exporting a private key is a sensitive operation.\n\n"
                 "Anyone with access to this file can impersonate you and decrypt your messages.\n\n"
                 "Store it securely and never share it."),
            QMessageBox::Ok | QMessageBox::Cancel, QMessageBox::Cancel);
        if (warn != QMessageBox::Ok)
            return;
    }

    QString email = uid.section(QLatin1Char('<'), 1, 1).section(QLatin1Char('>'), 0, 0).trimmed();
    if (email.isEmpty())
        email = uid.section(QLatin1Char(' '), 0, 0).trimmed();
    const QString keyIdShort = QStringLiteral("0x") + fpr.right(16);
    const QString typeTag = exportSecret ? QStringLiteral("SECRET") : QStringLiteral("public");
    const QString defaultName = email + QLatin1Char('_') + keyIdShort + QLatin1Char('_') + typeTag + QStringLiteral(".asc");

    const QString dest = QFileDialog::getSaveFileName(
        this, i18n("Export Key"),
        defaultName,
        i18n("ASCII Armored (*.asc);;Binary (*.gpg)"));

    if (dest.isEmpty())
        return;

    QStringList args = {QStringLiteral("--batch"),
                        QStringLiteral("--output"), dest};

    if (dest.endsWith(QLatin1String(".asc"), Qt::CaseInsensitive))
        args << QStringLiteral("--armor");

    if (exportSecret)
        args << QStringLiteral("--export-secret-keys");
    else
        args << QStringLiteral("--export");

    args << fpr;

    QProcess gpg;
    gpg.start(QStringLiteral("gpg"), args);

    if (!gpg.waitForFinished(10000)) {
        gpg.kill();
        gpg.waitForFinished(3000);
        QMessageBox::warning(this, i18n("Export Failed"), i18n("GPG timed out."));
        return;
    }

    if (gpg.exitCode() != 0) {
        QMessageBox::warning(this, i18n("Export Failed"),
                             QString::fromUtf8(gpg.readAllStandardError()));
    } else {
        QMessageBox::information(this, i18n("Export"),
                                 i18n("Key exported to:\n%1", dest));
    }
}

void SettingsDialog::onGenerateKey()
{
    KeyGenDialog dlg(this);
    if (dlg.exec() != QDialog::Accepted)
        return;

    QString config = dlg.batchConfig();

    QProcess gpg;
    gpg.start(QStringLiteral("gpg"),
              {QStringLiteral("--batch"), QStringLiteral("--gen-key")});

    if (!gpg.waitForStarted(5000)) {
        config.fill(QChar(0));
        QMessageBox::warning(this, i18n("Error"), i18n("Failed to start GPG."));
        return;
    }

    QByteArray configUtf8 = config.toUtf8();
    config.fill(QChar(0));
    gpg.write(configUtf8);
    configUtf8.fill('\0');
    gpg.closeWriteChannel();

    QApplication::setOverrideCursor(Qt::WaitCursor);
    bool finished = gpg.waitForFinished(60000);
    QApplication::restoreOverrideCursor();

    if (!finished) {
        gpg.kill();
        gpg.waitForFinished(3000);
        QMessageBox::warning(this, i18n("Error"), i18n("Key generation timed out."));
        return;
    }

    if (gpg.exitCode() != 0) {
        QMessageBox::warning(this, i18n("Error"),
                             QString::fromUtf8(gpg.readAllStandardError()));
    } else {
        QMessageBox::information(this, i18n("Key Generated"),
                                 i18n("Key generated successfully."));
        loadGpgKeys();
        populateDefaultKeyCombo();
    }
}

void SettingsDialog::onDeleteKey()
{
    auto *item = m_keyList->currentItem();
    if (!item)
        return;

    const QString fpr = item->data(0, Qt::UserRole).toString();
    const QString uid = item->text(0);

    bool ok = false;
    QString confirmation = QInputDialog::getText(
        this, i18n("Delete Key"),
        i18n("Delete key for:\n%1\n\nFingerprint: %2\n\nThis will permanently remove both public and private key.\n\nType DELETE to confirm:", uid, fpr),
        QLineEdit::Normal, QString(), &ok);

    if (!ok || confirmation.trimmed().compare(QLatin1String("DELETE"), Qt::CaseInsensitive) != 0)
        return;

    QProcess gpg;
    gpg.start(QStringLiteral("gpg"),
              {QStringLiteral("--batch"), QStringLiteral("--yes"),
               QStringLiteral("--delete-secret-and-public-key"), fpr});

    if (!gpg.waitForFinished(10000)) {
        gpg.kill();
        gpg.waitForFinished(3000);
        QMessageBox::warning(this, i18n("Error"), i18n("GPG timed out."));
        return;
    }

    if (gpg.exitCode() != 0) {
        QMessageBox::warning(this, i18n("Error"),
                             QString::fromUtf8(gpg.readAllStandardError()));
    } else {
        QMessageBox::information(this, i18n("Key Deleted"),
                                 i18n("Key deleted successfully."));
        loadGpgKeys();
        populateDefaultKeyCombo();
    }
}

void SettingsDialog::onKeyDetails()
{
    auto *item = m_keyList->currentItem();
    if (!item)
        return;

    const QString fpr = item->data(0, Qt::UserRole).toString();

    QProcess gpg;
    gpg.start(QStringLiteral("gpg"),
              {QStringLiteral("--batch"),
               QStringLiteral("--list-secret-keys"),
               QStringLiteral("--keyid-format"), QStringLiteral("0xlong"),
               QStringLiteral("--fingerprint"),
               QStringLiteral("--fingerprint"),
               fpr});

    if (!gpg.waitForFinished(5000)) {
        gpg.kill();
        gpg.waitForFinished(3000);
        return;
    }

    const QString output = QString::fromUtf8(gpg.readAllStandardOutput());

    QDialog dlg(this);
    dlg.setWindowTitle(i18n("Key Details"));
    dlg.setMinimumSize(550, 350);

    auto *layout = new QVBoxLayout(&dlg);

    auto *text = new QPlainTextEdit(&dlg);
    text->setReadOnly(true);
    text->setPlainText(output);
    text->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
    text->setAccessibleName(i18n("Key details output"));
    layout->addWidget(text);

    auto *closeBtn = new QDialogButtonBox(QDialogButtonBox::Close, &dlg);
    connect(closeBtn, &QDialogButtonBox::rejected, &dlg, &QDialog::close);
    layout->addWidget(closeBtn);

    dlg.exec();
}

void SettingsDialog::onChangePassphrase()
{
    auto *item = m_keyList->currentItem();
    if (!item)
        return;

    const QString fpr = item->data(0, Qt::UserRole).toString();

    QProcess gpg;
    gpg.start(QStringLiteral("gpg"),
              {QStringLiteral("--status-fd"), QStringLiteral("2"),
               QStringLiteral("--passwd"), fpr});

    if (!gpg.waitForFinished(60000)) {
        gpg.kill();
        gpg.waitForFinished(3000);
        QMessageBox::warning(this, i18n("Error"), i18n("GPG timed out."));
        return;
    }

    const QString status = QString::fromUtf8(gpg.readAllStandardError());

    if (gpg.exitCode() != 0 || status.contains(QLatin1String("[GNUPG:] ERROR"))
        || status.contains(QLatin1String("[GNUPG:] CANCEL"))) {
        if (!status.contains(QLatin1String("[GNUPG:] CANCEL"))) {
            const QString err = status.section(QLatin1String("[GNUPG:]"), 0, 0).trimmed();
            if (!err.isEmpty())
                QMessageBox::warning(this, i18n("Error"), err);
        }
    } else {
        QMessageBox::information(this, i18n("Passphrase Changed"),
                                 i18n("Passphrase changed successfully."));
    }
}

void SettingsDialog::onSelectionChanged()
{
    bool hasSelection = m_keyList->currentItem() != nullptr;
    m_exportBtn->setEnabled(hasSelection);
    m_deleteBtn->setEnabled(hasSelection);
    m_detailsBtn->setEnabled(hasSelection);
    m_changePassBtn->setEnabled(hasSelection);
}

QString SettingsDialog::gpgKeyId() const
{
    return m_defaultKeyCombo->currentData().toString();
}

void SettingsDialog::setGpgKeyId(const QString &keyId)
{
    int idx = m_defaultKeyCombo->findData(keyId);
    if (idx >= 0)
        m_defaultKeyCombo->setCurrentIndex(idx);
}

void SettingsDialog::populateDefaultKeyCombo()
{
    const QString previous = m_defaultKeyCombo->currentData().toString();
    m_defaultKeyCombo->clear();
    m_defaultKeyCombo->addItem(i18n("(none)"), QString());

    for (int i = 0; i < m_keyList->topLevelItemCount(); ++i) {
        auto *item = m_keyList->topLevelItem(i);
        const QString fpr = item->data(0, Qt::UserRole).toString();
        const QString label = item->text(0) + QStringLiteral("  [") + fpr.right(8) + QStringLiteral("]");
        m_defaultKeyCombo->addItem(label, fpr);
    }

    if (!previous.isEmpty()) {
        int idx = m_defaultKeyCombo->findData(previous);
        if (idx >= 0)
            m_defaultKeyCombo->setCurrentIndex(idx);
    }
}

bool SettingsDialog::storeInWallet() const
{
    return m_walletCheck->isChecked();
}

void SettingsDialog::setStoreInWallet(bool store)
{
    m_walletCheck->setChecked(store);
}

bool SettingsDialog::rememberFiles() const
{
    return m_rememberCheck->isChecked();
}

void SettingsDialog::setRememberFiles(bool remember)
{
    m_rememberCheck->setChecked(remember);
}
