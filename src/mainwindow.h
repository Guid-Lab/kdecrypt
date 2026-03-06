// SPDX-FileCopyrightText: 2026 Guid <guid@guid.pl>
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <KXmlGuiWindow>
#include <QDateTime>
#include <QList>
#include <QStringList>
#include "cryptohelper.h"
#include "decryptedfile.h"
#include "gpgengine.h"
#include "walletmanager.h"

class QTreeWidget;
class QTreeWidgetItem;

class MainWindow : public KXmlGuiWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow() override;

    void openFile(const QString &path, const QDateTime &originalTime = {});

protected:
    void closeEvent(QCloseEvent *event) override;
    void dragEnterEvent(QDragEnterEvent *event) override;
    void dropEvent(QDropEvent *event) override;

private Q_SLOTS:
    void onOpenFile();
    void onEncryptFile();
    void onSettings();
    void onItemDoubleClicked(QTreeWidgetItem *item, int column);
    void onSaveDecrypted();
    void onOpenDecrypted();
    void onRemoveItem();
    void onClearAll();
    void onSwitchLanguage();

private:
    void setupActions();
    void initCryptoKey();
    void loadSettings();
    void saveSettings();
    void loadRememberedFiles();
    void saveRememberedFiles();
    void cleanupTempFiles();
    QString requestPassphrase();
    int currentFileIndex() const;

    QTreeWidget *m_fileList;
    QList<DecryptedFile> m_files;
    GpgEngine m_gpg;
    WalletManager m_wallet;
    CryptoHelper m_crypto;
    QString m_gpgKeyId;
    bool m_useWallet = true;
    bool m_rememberFiles = true;
    QString m_tmpDirPath;
    QStringList m_tmpFiles;
};
