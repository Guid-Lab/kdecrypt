// SPDX-FileCopyrightText: 2026 Guid <guid@guid.pl>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "mainwindow.h"
#include "encryptdialog.h"
#include "settingsdialog.h"

#include <KActionCollection>
#include <KLocalizedString>
#include <KStandardAction>

#include <QAction>
#include <QApplication>
#include <QDesktopServices>
#include <QFileDialog>
#include <QHeaderView>
#include <QInputDialog>
#include <QLocale>
#include <QMessageBox>
#include <QMimeDatabase>
#include <QProcess>
#include <QSettings>
#include <QStatusBar>
#include <QStandardPaths>
#include <QTreeWidget>
#include <QDir>
#include <QDirIterator>
#include <QCloseEvent>
#include <QDragEnterEvent>
#include <QDropEvent>
#include <QMimeData>
#include <QUrl>

MainWindow::MainWindow(QWidget *parent)
    : KXmlGuiWindow(parent)
{
    setWindowTitle(i18n("KDecrypt"));

    m_fileList = new QTreeWidget(this);
    m_fileList->setHeaderLabels({i18n("File"), i18n("Size"), i18n("Key"), i18n("Decrypted at")});
    m_fileList->setRootIsDecorated(false);
    m_fileList->setAlternatingRowColors(true);
    m_fileList->header()->setStretchLastSection(true);
    m_fileList->setContextMenuPolicy(Qt::ActionsContextMenu);
    m_fileList->setSelectionMode(QAbstractItemView::SingleSelection);
    m_fileList->setAccessibleName(i18n("Decrypted files list"));
    m_fileList->setAccessibleDescription(i18n("List of decrypted files. Use context menu or keyboard shortcuts to open, save, or remove files."));

    connect(m_fileList, &QTreeWidget::itemDoubleClicked,
            this, &MainWindow::onItemDoubleClicked);

    setCentralWidget(m_fileList);
    setAcceptDrops(true);
    setupActions();
    setupGUI(Default, QStringLiteral("kdecryptui.rc"));

    if (auto *a = actionCollection()->action(QStringLiteral("switch_application_language")))
        actionCollection()->removeAction(a);

    loadSettings();

    if (!m_wallet.open(winId()))
        QMessageBox::warning(this, i18n("Warning"),
                             i18n("Could not open KDE Wallet. Passphrases will not be stored."));
    initCryptoKey();
    m_gpg.setPassphraseProvider([this]() { return requestPassphrase(); });

    const QString cacheOpen = QStandardPaths::writableLocation(QStandardPaths::CacheLocation)
                              + QStringLiteral("/open");
    if (QDir(cacheOpen).exists()) {
        QDirIterator it(cacheOpen, QDir::Files, QDirIterator::Subdirectories);
        while (it.hasNext())
            GpgEngine::secureRemove(it.next());
        QDir(cacheOpen).removeRecursively();
    }

    loadRememberedFiles();

    resize(750, 500);
}

MainWindow::~MainWindow()
{
    saveRememberedFiles();
    saveSettings();
    cleanupTempFiles();
    for (auto &df : m_files)
        df.data.fill('\0');
}

void MainWindow::initCryptoKey()
{
    static const QString walletKey = QStringLiteral("kdecrypt-storage-key");
    QString storedKey = m_wallet.retrievePassphrase(walletKey);
    if (!storedKey.isEmpty()) {
        m_crypto.setKey(QByteArray::fromHex(storedKey.toLatin1()));
        storedKey.fill(QChar(0));
    } else {
        QByteArray key = CryptoHelper::generateKey();
        if (key.isEmpty()) {
            QMessageBox::critical(this, i18n("Error"),
                                  i18n("Failed to generate cryptographic key. "
                                       "In-memory encryption is disabled. "
                                       "Decrypted data will NOT be protected."));
            return;
        }
        m_crypto.setKey(key);
        QByteArray hexKey = key.toHex();
        QString hexStr = QString::fromLatin1(hexKey);
        m_wallet.storePassphrase(walletKey, hexStr);
        hexStr.fill(QChar(0));
        hexKey.fill('\0');
        key.fill('\0');
    }
}

void MainWindow::cleanupTempFiles()
{
    for (const auto &path : m_tmpFiles)
        GpgEngine::secureRemove(path);
    m_tmpFiles.clear();
    if (!m_tmpDirPath.isEmpty())
        QDir(m_tmpDirPath).removeRecursively();
}

void MainWindow::setupActions()
{
    auto *openAction = KStandardAction::open(this, &MainWindow::onOpenFile, actionCollection());
    openAction->setText(i18n("Decrypt File..."));
    openAction->setIcon(QIcon::fromTheme(QStringLiteral("document-open")));
    openAction->setToolTip(i18n("Open and decrypt a PGP/GPG encrypted file (Ctrl+O)"));

    auto *encryptAction = new QAction(QIcon::fromTheme(QStringLiteral("document-encrypt")),
                                      i18n("Encrypt File..."), this);
    encryptAction->setShortcut(QKeySequence(QStringLiteral("Ctrl+E")));
    encryptAction->setToolTip(i18n("Encrypt a file for selected recipients (Ctrl+E)"));
    connect(encryptAction, &QAction::triggered, this, &MainWindow::onEncryptFile);
    actionCollection()->addAction(QStringLiteral("encrypt_file"), encryptAction);

    auto *keysAction = new QAction(QIcon::fromTheme(QStringLiteral("gpg")),
                                      i18n("Key Manager..."), this);
    keysAction->setShortcut(QKeySequence(QStringLiteral("Ctrl+K")));
    keysAction->setToolTip(i18n("Manage GPG keys and application settings (Ctrl+K)"));
    connect(keysAction, &QAction::triggered, this, &MainWindow::onSettings);
    actionCollection()->addAction(QStringLiteral("key_manager"), keysAction);

    auto *langAction = new QAction(QIcon::fromTheme(QStringLiteral("preferences-desktop-locale")),
                                    i18n("Switch Language..."), this);
    langAction->setToolTip(i18n("Change application language"));
    connect(langAction, &QAction::triggered, this, &MainWindow::onSwitchLanguage);
    actionCollection()->addAction(QStringLiteral("switch_language"), langAction);

    KStandardAction::quit(this, &QWidget::close, actionCollection());

    auto *saveAction = new QAction(QIcon::fromTheme(QStringLiteral("document-save-as")),
                                   i18n("Save Decrypted..."), this);
    saveAction->setShortcut(QKeySequence(QStringLiteral("Ctrl+S")));
    saveAction->setToolTip(i18n("Save the selected decrypted file to disk (Ctrl+S)"));
    connect(saveAction, &QAction::triggered, this, &MainWindow::onSaveDecrypted);
    actionCollection()->addAction(QStringLiteral("save_decrypted"), saveAction);
    m_fileList->addAction(saveAction);

    auto *viewAction = new QAction(QIcon::fromTheme(QStringLiteral("document-preview")),
                                   i18n("Open with Default App"), this);
    viewAction->setToolTip(i18n("Open the selected file with its default application"));
    connect(viewAction, &QAction::triggered, this, &MainWindow::onOpenDecrypted);
    actionCollection()->addAction(QStringLiteral("open_decrypted"), viewAction);
    m_fileList->addAction(viewAction);

    auto *removeAction = new QAction(QIcon::fromTheme(QStringLiteral("list-remove")),
                                     i18n("Remove from List"), this);
    removeAction->setShortcut(QKeySequence::Delete);
    removeAction->setToolTip(i18n("Remove the selected file from the list and wipe from memory (Del)"));
    connect(removeAction, &QAction::triggered, this, &MainWindow::onRemoveItem);
    actionCollection()->addAction(QStringLiteral("remove_item"), removeAction);
    m_fileList->addAction(removeAction);

    auto *clearAction = new QAction(QIcon::fromTheme(QStringLiteral("edit-clear-list")),
                                    i18n("Clear All"), this);
    clearAction->setToolTip(i18n("Remove all files from the list and wipe from memory"));
    connect(clearAction, &QAction::triggered, this, &MainWindow::onClearAll);
    actionCollection()->addAction(QStringLiteral("clear_all"), clearAction);
    m_fileList->addAction(clearAction);
}

void MainWindow::loadSettings()
{
    QSettings settings(QStringLiteral("GuidLab"), QStringLiteral("kdecrypt"));
    m_gpgKeyId = settings.value(QStringLiteral("gpgKeyId")).toString();
    m_useWallet = settings.value(QStringLiteral("useWallet"), true).toBool();
    m_rememberFiles = settings.value(QStringLiteral("rememberFiles"), true).toBool();
}

void MainWindow::saveSettings()
{
    QSettings settings(QStringLiteral("GuidLab"), QStringLiteral("kdecrypt"));
    settings.setValue(QStringLiteral("gpgKeyId"), m_gpgKeyId);
    settings.setValue(QStringLiteral("useWallet"), m_useWallet);
    settings.setValue(QStringLiteral("rememberFiles"), m_rememberFiles);
}

void MainWindow::loadRememberedFiles()
{
    if (!m_rememberFiles)
        return;

    QSettings settings(QStringLiteral("GuidLab"), QStringLiteral("kdecrypt"));
    const QStringList entries = settings.value(QStringLiteral("rememberedFiles")).toStringList();
    for (const auto &entry : entries) {
        const int sep = entry.indexOf(QLatin1Char('|'));
        QDateTime originalTime;
        QString path;
        if (sep > 0) {
            bool ok = false;
            qint64 ts = entry.left(sep).toLongLong(&ok);
            if (ok && ts > 0)
                originalTime = QDateTime::fromSecsSinceEpoch(ts);
            path = entry.mid(sep + 1);
        } else {
            path = entry;
        }
        if (QFile::exists(path))
            openFile(path, originalTime);
    }
}

void MainWindow::saveRememberedFiles()
{
    QSettings settings(QStringLiteral("GuidLab"), QStringLiteral("kdecrypt"));
    if (!m_rememberFiles) {
        settings.remove(QStringLiteral("rememberedFiles"));
        return;
    }

    QStringList entries;
    for (const auto &df : m_files) {
        if (!df.sourcePath.isEmpty())
            entries << QString::number(df.decryptedAt.toSecsSinceEpoch())
                       + QLatin1Char('|') + df.sourcePath;
    }
    settings.setValue(QStringLiteral("rememberedFiles"), entries);
}

void MainWindow::openFile(const QString &path, const QDateTime &originalTime)
{
    for (const auto &existing : m_files) {
        if (existing.sourcePath == path) {
            statusBar()->showMessage(i18n("File already open: %1", QFileInfo(path).fileName()), 3000);
            return;
        }
    }

    const qint64 fileSize = QFileInfo(path).size();
    static constexpr qint64 LARGE_FILE_THRESHOLD = 100LL * 1024 * 1024;
    if (fileSize > LARGE_FILE_THRESHOLD) {
        auto answer = QMessageBox::question(
            this, i18n("Large File"),
            i18n("This file is %1 MB. Decrypting large files may use significant memory and time.\n\nContinue?",
                 QString::number(fileSize / (1024.0 * 1024.0), 'f', 1)));
        if (answer != QMessageBox::Yes)
            return;
    }

    auto result = m_gpg.decrypt(path);
    if (!result.success) {
        QMessageBox msgBox(this);
        msgBox.setIcon(QMessageBox::Warning);
        msgBox.setWindowTitle(i18n("Decryption Failed"));
        msgBox.setText(result.error);
        if (!result.rawOutput.isEmpty())
            msgBox.setDetailedText(result.rawOutput);

        if (!result.missingKeys.isEmpty()) {
            auto *importBtn = msgBox.addButton(i18n("Import Key..."), QMessageBox::ActionRole);
            msgBox.addButton(QMessageBox::Close);
            msgBox.exec();
            if (msgBox.clickedButton() == (QAbstractButton*)importBtn) {
                const QString file = QFileDialog::getOpenFileName(
                    this, i18n("Import GPG Key"), QString(),
                    i18n("GPG Key Files (*.asc *.gpg *.pgp *.key);;All Files (*)"));
                if (!file.isEmpty()) {
                    QProcess gpg;
                    gpg.start(QStringLiteral("gpg"),
                              {QStringLiteral("--batch"), QStringLiteral("--import"), file});
                    bool finished = gpg.waitForFinished(10000);
                    if (!finished) {
                        gpg.kill();
                        gpg.waitForFinished(3000);
                    }
                    if (finished && gpg.exitCode() == 0) {
                        QMessageBox::information(this, i18n("Import"),
                            i18n("Key imported. Retrying decryption..."));
                        openFile(path);
                    } else {
                        QMessageBox::warning(this, i18n("Import Failed"),
                            QString::fromUtf8(gpg.readAllStandardError()));
                    }
                }
            }
        } else {
            msgBox.exec();
        }
        return;
    }

    DecryptedFile df;
    df.sourcePath = path;
    df.dataSize = result.data.size();

    QString name = QFileInfo(path).fileName();
    for (const auto &ext : {".pgp", ".gpg", ".asc"}) {
        if (name.endsWith(QLatin1String(ext), Qt::CaseInsensitive)) {
            name.chop(qstrlen(ext));
            break;
        }
    }
    if (name.isEmpty())
        name = QStringLiteral("decrypted");
    df.originalName = name;

    QMimeDatabase mimeDb;
    QMimeType mime = mimeDb.mimeTypeForFileNameAndData(df.originalName, result.data.left(4096));

    df.data = m_crypto.encrypt(result.data);
    result.data.fill('\0');

    if (df.data.isEmpty()) {
        QMessageBox::warning(this, i18n("Error"),
                             i18n("Failed to store decrypted data in memory."));
        return;
    }
    df.decryptedAt = originalTime.isValid() ? originalTime : QDateTime::currentDateTime();
    df.decryptedWithKey = result.keyUsed;

    m_files.append(df);

    auto *item = new QTreeWidgetItem(m_fileList);
    item->setText(0, df.originalName);
    item->setText(1, df.sizeString());
    item->setText(2, df.decryptedWithKey.isEmpty() ? i18n("unknown") : df.decryptedWithKey);
    item->setText(3, QLocale().toString(df.decryptedAt, QLocale::ShortFormat));
    item->setData(0, Qt::UserRole, df.sourcePath);
    item->setIcon(0, QIcon::fromTheme(mime.iconName()));

    for (int i = 0; i < m_fileList->columnCount(); ++i)
        m_fileList->resizeColumnToContents(i);

    statusBar()->showMessage(i18n("Decrypted: %1", df.originalName), 3000);
}

void MainWindow::onOpenFile()
{
    const QStringList files = QFileDialog::getOpenFileNames(
        this, i18n("Open Encrypted Files"), QString(),
        i18n("PGP Encrypted Files (*.pgp *.gpg *.asc);;All Files (*)"));

    for (const auto &f : files)
        openFile(f);
}

void MainWindow::onEncryptFile()
{
    const QString file = QFileDialog::getOpenFileName(
        this, i18n("Select File to Encrypt"), QString(),
        i18n("All Files (*)"));

    if (file.isEmpty())
        return;

    EncryptDialog dlg(this);
    if (dlg.exec() != QDialog::Accepted)
        return;

    const QString defaultExt = dlg.armorOutput() ? QStringLiteral(".asc") : QStringLiteral(".gpg");
    const QString defaultPath = file + defaultExt;

    const QString outputPath = QFileDialog::getSaveFileName(
        this, i18n("Save Encrypted File"), defaultPath,
        i18n("PGP Binary (*.gpg);;ASCII Armored (*.asc);;All Files (*)"));

    if (outputPath.isEmpty())
        return;

    if (QFileInfo(file).absoluteFilePath() == QFileInfo(outputPath).absoluteFilePath()) {
        QMessageBox::warning(this, i18n("Error"),
                             i18n("Output file cannot be the same as the input file."));
        return;
    }

    const bool armor = dlg.armorOutput() || outputPath.endsWith(QLatin1String(".asc"), Qt::CaseInsensitive);

    static constexpr qint64 LARGE_ENCRYPT_THRESHOLD = 100LL * 1024 * 1024;
    const qint64 encryptFileSize = QFileInfo(file).size();
    if (encryptFileSize > LARGE_ENCRYPT_THRESHOLD) {
        auto answer = QMessageBox::question(
            this, i18n("Large File"),
            i18n("This file is %1 MB. Encrypting large files may take significant time.\n\nContinue?",
                 QString::number(encryptFileSize / (1024.0 * 1024.0), 'f', 1)));
        if (answer != QMessageBox::Yes)
            return;
    }

    QApplication::setOverrideCursor(Qt::WaitCursor);
    auto result = m_gpg.encrypt(file, outputPath, dlg.selectedRecipients(),
                                 dlg.signingKey(), armor);
    QApplication::restoreOverrideCursor();

    if (!result.success) {
        QMessageBox::warning(this, i18n("Encryption Failed"), result.error);
    } else {
        QMessageBox::information(this, i18n("Encrypted"),
                                 i18n("File encrypted successfully:\n%1", outputPath));
    }
}

void MainWindow::onSettings()
{
    SettingsDialog dlg(this);
    dlg.setGpgKeyId(m_gpgKeyId);
    dlg.setStoreInWallet(m_useWallet);
    dlg.setRememberFiles(m_rememberFiles);

    if (dlg.exec() == QDialog::Accepted) {
        m_gpgKeyId = dlg.gpgKeyId();
        m_useWallet = dlg.storeInWallet();
        m_rememberFiles = dlg.rememberFiles();
        saveSettings();
    }
}

void MainWindow::onItemDoubleClicked(QTreeWidgetItem *item, int)
{
    Q_UNUSED(item);
    onOpenDecrypted();
}

void MainWindow::onOpenDecrypted()
{
    int idx = currentFileIndex();
    if (idx < 0)
        return;

    const auto &df = m_files.at(idx);

    if (m_tmpDirPath.isEmpty()) {
        m_tmpDirPath = QStandardPaths::writableLocation(QStandardPaths::CacheLocation)
                       + QStringLiteral("/open");
        QDir().mkpath(m_tmpDirPath);
        QFile::setPermissions(m_tmpDirPath,
            QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner);
    }

    const QString subDir = m_tmpDirPath + QStringLiteral("/")
        + QString::number(qHash(df.sourcePath), 16);
    QDir().mkpath(subDir);
    QFile::setPermissions(subDir,
        QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner);
    const QString tmpPath = subDir + QStringLiteral("/") + df.originalName;
    QByteArray plaintext = m_crypto.decrypt(df.data);
    if (plaintext.isEmpty()) {
        QMessageBox::warning(this, i18n("Error"), i18n("Failed to decrypt data from memory."));
        return;
    }

    QFile out(tmpPath);
    if (out.open(QIODevice::WriteOnly)) {
        out.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner);
        out.write(plaintext);
        plaintext.fill('\0');
        out.close();
        if (!m_tmpFiles.contains(tmpPath))
            m_tmpFiles << tmpPath;
        QDesktopServices::openUrl(QUrl::fromLocalFile(tmpPath));
    } else {
        plaintext.fill('\0');
        QMessageBox::warning(this, i18n("Error"), i18n("Failed to write temporary file."));
    }
}

void MainWindow::onSaveDecrypted()
{
    int idx = currentFileIndex();
    if (idx < 0)
        return;

    const auto &df = m_files.at(idx);
    const QString dest = QFileDialog::getSaveFileName(
        this, i18n("Save Decrypted File"), df.originalName);

    if (dest.isEmpty())
        return;

    QByteArray plaintext = m_crypto.decrypt(df.data);
    if (plaintext.isEmpty()) {
        QMessageBox::warning(this, i18n("Error"), i18n("Failed to decrypt data from memory."));
        return;
    }

    QFile out(dest);
    if (out.open(QIODevice::WriteOnly)) {
        out.write(plaintext);
        plaintext.fill('\0');
        out.close();
        statusBar()->showMessage(i18n("Saved: %1", dest), 3000);
    } else {
        plaintext.fill('\0');
        QMessageBox::warning(this, i18n("Error"),
                             i18n("Failed to save file: %1", out.errorString()));
    }
}

void MainWindow::onRemoveItem()
{
    int idx = currentFileIndex();
    if (idx < 0)
        return;

    auto answer = QMessageBox::question(
        this, i18n("Remove File"),
        i18n("Remove \"%1\" from the list and wipe from memory?", m_files.at(idx).originalName));
    if (answer != QMessageBox::Yes)
        return;

    const QString removedName = m_files.at(idx).originalName;
    m_files[idx].data.fill('\0');
    m_files.removeAt(idx);
    delete m_fileList->currentItem();
    statusBar()->showMessage(i18n("Removed: %1", removedName), 3000);
}

void MainWindow::onClearAll()
{
    if (m_files.isEmpty())
        return;

    auto answer = QMessageBox::question(
        this, i18n("Clear All"),
        i18n("Remove all decrypted files from the list?"));

    if (answer != QMessageBox::Yes)
        return;

    for (auto &df : m_files)
        df.data.fill('\0');
    m_files.clear();
    m_fileList->clear();
    statusBar()->showMessage(i18n("All files cleared."), 3000);
}

QString MainWindow::requestPassphrase()
{
    const QString walletKey = m_gpgKeyId.isEmpty()
        ? QStringLiteral("default") : m_gpgKeyId;

    if (m_useWallet) {
        QString stored = m_wallet.retrievePassphrase(walletKey);
        if (!stored.isEmpty()) {
            QString ret = stored;
            stored.fill(QChar(0));
            return ret;
        }
    }

    bool ok = false;
    const QString label = m_gpgKeyId.isEmpty()
        ? i18n("Enter passphrase for GPG key:")
        : i18n("Enter passphrase for GPG key %1:", m_gpgKeyId.right(8));
    QString passphrase = QInputDialog::getText(
        this, i18n("Passphrase"),
        label,
        QLineEdit::Password, QString(), &ok);

    if (!ok)
        return {};

    if (m_useWallet && !passphrase.isEmpty())
        m_wallet.storePassphrase(walletKey, passphrase);

    return passphrase;
}

int MainWindow::currentFileIndex() const
{
    auto *item = m_fileList->currentItem();
    if (!item)
        return -1;
    const QString path = item->data(0, Qt::UserRole).toString();
    for (int i = 0; i < m_files.size(); ++i) {
        if (m_files[i].sourcePath == path)
            return i;
    }
    return -1;
}

void MainWindow::closeEvent(QCloseEvent *event)
{
    if (!m_files.isEmpty() && !m_rememberFiles) {
        auto answer = QMessageBox::question(
            this, i18n("Quit"),
            i18n("There are %1 decrypted file(s) in memory. They will be securely wiped.\n\nQuit?",
                 m_files.size()));
        if (answer != QMessageBox::Yes) {
            event->ignore();
            return;
        }
    }
    event->accept();
}

void MainWindow::onSwitchLanguage()
{
    QStringList codes = {
        QStringLiteral("en"),
        QStringLiteral("pl"),
        QStringLiteral("de"),
        QStringLiteral("fr"),
        QStringLiteral("zh_CN"),
        QStringLiteral("ja"),
    };

    QStringList labels;
    for (const auto &code : codes)
        labels << QLocale(code).nativeLanguageName();

    QSettings rc(QStandardPaths::writableLocation(QStandardPaths::GenericConfigLocation)
                 + QStringLiteral("/kdecryptrc"), QSettings::IniFormat);
    QString currentLang = rc.value(QStringLiteral("Locale/Language")).toString();
    if (currentLang.isEmpty())
        currentLang = QLocale().name().section(QLatin1Char('_'), 0, 0);

    int currentIdx = 0;
    for (int i = 0; i < codes.size(); ++i) {
        if (codes[i] == currentLang || codes[i].section(QLatin1Char('_'), 0, 0) == currentLang) {
            labels[i] += QStringLiteral(" ✓");
            currentIdx = i;
        }
    }

    bool ok = false;
    const QString choice = QInputDialog::getItem(
        this, i18n("Switch Language"), i18n("Select language:"),
        labels, currentIdx, false, &ok);

    if (!ok)
        return;

    const int idx = labels.indexOf(choice);
    if (idx < 0)
        return;

    const QString lang = codes[idx];

    if (lang == currentLang || (currentLang.isEmpty() && lang == QLatin1String("en"))) {
        statusBar()->showMessage(i18n("Language already active."), 3000);
        return;
    }

    rc.beginGroup(QStringLiteral("Locale"));
    rc.setValue(QStringLiteral("Language"), lang);
    rc.endGroup();

    KLocalizedString::setLanguages({lang});
    if (!m_files.isEmpty() && !m_rememberFiles) {
        auto answer = QMessageBox::question(
            this, i18n("Language Changed"),
            i18n("Changing language requires restarting. %1 decrypted file(s) in memory will be lost.\n\nRestart now or apply on next launch?",
                 m_files.size()),
            QMessageBox::Yes | QMessageBox::No);
        if (answer != QMessageBox::Yes) {
            statusBar()->showMessage(i18n("Language will change on next launch."), 5000);
            return;
        }
    } else {
        auto answer = QMessageBox::question(
            this, i18n("Language Changed"),
            i18n("Restart now to apply the new language?"),
            QMessageBox::Yes | QMessageBox::No);
        if (answer != QMessageBox::Yes) {
            statusBar()->showMessage(i18n("Language will change on next launch."), 5000);
            return;
        }
    }

    QProcess::startDetached(QApplication::applicationFilePath(), QStringList());
    QApplication::quit();
}

void MainWindow::dragEnterEvent(QDragEnterEvent *event)
{
    if (event->mimeData()->hasUrls())
        event->acceptProposedAction();
}

void MainWindow::dropEvent(QDropEvent *event)
{
    const auto urls = event->mimeData()->urls();
    for (const auto &url : urls) {
        if (url.isLocalFile())
            openFile(url.toLocalFile());
    }
}
