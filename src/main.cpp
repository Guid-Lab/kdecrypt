// SPDX-FileCopyrightText: 2026 Guid <guid@guid.pl>
// SPDX-License-Identifier: GPL-3.0-or-later

#include <QApplication>
#include <QCommandLineParser>
#include <QSettings>
#include <QStandardPaths>
#include <KAboutData>
#include <KDBusService>
#include <KLocalizedString>
#include <KWindowSystem>
#include <QIcon>
#include "mainwindow.h"
#include "version.h"

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    KLocalizedString::setApplicationDomain("kdecrypt");

    QSettings langRc(QStandardPaths::writableLocation(QStandardPaths::GenericConfigLocation)
                     + QStringLiteral("/kdecryptrc"), QSettings::IniFormat);
    const QString lang = langRc.value(QStringLiteral("Locale/Language")).toString();
    if (!lang.isEmpty())
        KLocalizedString::setLanguages({lang});

    KAboutData aboutData(
        QStringLiteral("kdecrypt"),
        i18n("KDecrypt"),
        QStringLiteral(KDECRYPT_VERSION),
        i18n("PGP/GPG file encryption and decryption manager for KDE Plasma"),
        KAboutLicense::GPL_V3,
        i18n("(c) 2026 Guid"),
        QString(),
        QStringLiteral("https://github.com/Guid-Lab/kdecrypt"),
        QStringLiteral("https://github.com/Guid-Lab/kdecrypt/issues")
    );
    aboutData.addAuthor(
        i18n("Guid"),
        i18n("Lead Developer"),
        QStringLiteral("guid@guid.pl"),
        QStringLiteral("https://github.com/Guid-Lab")
    );
    aboutData.setOrganizationDomain("guid.pl");
    aboutData.setDesktopFileName(QStringLiteral("org.guidlab.kdecrypt"));

    KAboutData::setApplicationData(aboutData);
    app.setWindowIcon(QIcon::fromTheme(QStringLiteral("kdecrypt")));

    QCommandLineParser parser;
    aboutData.setupCommandLine(&parser);
    parser.addPositionalArgument(
        QStringLiteral("files"),
        i18n("Encrypted files to open"),
        QStringLiteral("[files...]")
    );
    parser.process(app);
    aboutData.processCommandLine(&parser);

    KDBusService service(KDBusService::Unique);

    MainWindow window;

    auto openFilesFromArgs = [&window, &parser]() {
        const QStringList files = parser.positionalArguments();
        for (const auto &f : files)
            window.openFile(f);
        window.show();
        window.raise();
        KWindowSystem::activateWindow(window.windowHandle());
    };

    QObject::connect(&service, &KDBusService::activateRequested,
                     &window, [&window](const QStringList &args, const QString &) {
        QCommandLineParser p;
        p.addPositionalArgument(QStringLiteral("files"), QString(), QStringLiteral("[files...]"));
        p.parse(args);
        const QStringList files = p.positionalArguments();
        for (const auto &f : files)
            window.openFile(f);
        window.show();
        window.raise();
        KWindowSystem::activateWindow(window.windowHandle());
    });

    openFilesFromArgs();
    return app.exec();
}
