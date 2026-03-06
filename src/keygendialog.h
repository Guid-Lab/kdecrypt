// SPDX-FileCopyrightText: 2026 Guid <guid@guid.pl>
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <QDialog>

class QComboBox;
class QLineEdit;
class QDateEdit;
class QCheckBox;

class KeyGenDialog : public QDialog
{
    Q_OBJECT

public:
    explicit KeyGenDialog(QWidget *parent = nullptr);

    QString batchConfig();

private Q_SLOTS:
    void onKeyTypeChanged();
    void onSubkeyTypeChanged();
    void onNoExpiryToggled(bool checked);

private:
    void populateKeySizes(QComboBox *combo, const QString &type);

    QLineEdit *m_nameEdit;
    QLineEdit *m_emailEdit;
    QLineEdit *m_commentEdit;
    QComboBox *m_keyTypeCombo;
    QComboBox *m_keySizeCombo;
    QComboBox *m_subkeyTypeCombo;
    QComboBox *m_subkeySizeCombo;
    QDateEdit *m_expiryDate;
    QCheckBox *m_noExpiryCheck;
    QLineEdit *m_passphraseEdit;
    QLineEdit *m_passphraseConfirmEdit;
};
