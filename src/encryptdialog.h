// SPDX-FileCopyrightText: 2026 Guid <guid@guid.pl>
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <QDialog>
#include <QStringList>

class QTreeWidget;
class QComboBox;
class QCheckBox;

class EncryptDialog : public QDialog
{
    Q_OBJECT

public:
    explicit EncryptDialog(QWidget *parent = nullptr);

    QStringList selectedRecipients() const;
    QString ownKey() const;
    QString signingKey() const;
    bool armorOutput() const;

private:
    void loadPublicKeys();
    void loadSecretKeys();

    QTreeWidget *m_recipientList;
    QComboBox *m_ownKeyCombo;
    QCheckBox *m_signCheck;
    QCheckBox *m_armorCheck;
};
