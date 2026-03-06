// SPDX-FileCopyrightText: 2026 Guid <guid@guid.pl>
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <QDialog>

class QCheckBox;
class QComboBox;
class QTreeWidget;
class QTreeWidgetItem;
class QPushButton;

class SettingsDialog : public QDialog
{
    Q_OBJECT

public:
    explicit SettingsDialog(QWidget *parent = nullptr);

    QString gpgKeyId() const;
    void setGpgKeyId(const QString &keyId);

    bool storeInWallet() const;
    void setStoreInWallet(bool store);

    bool rememberFiles() const;
    void setRememberFiles(bool remember);

private Q_SLOTS:
    void onImportKey();
    void onExportKey();
    void onGenerateKey();
    void onDeleteKey();
    void onKeyDetails();
    void onChangePassphrase();
    void onSelectionChanged();

private:
    void loadGpgKeys();
    void populateDefaultKeyCombo();

    QTreeWidget *m_keyList;
    QComboBox *m_defaultKeyCombo;
    QPushButton *m_exportBtn;
    QPushButton *m_deleteBtn;
    QPushButton *m_detailsBtn;
    QPushButton *m_changePassBtn;
    QCheckBox *m_walletCheck;
    QCheckBox *m_rememberCheck;
};
