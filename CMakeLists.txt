# SPDX-FileCopyrightText: 2026 Guid <guid@guid.pl>
# SPDX-License-Identifier: GPL-3.0-or-later

cmake_minimum_required(VERSION 3.20)

project(kdecrypt VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

find_package(ECM 6.0 REQUIRED NO_MODULE)
set(CMAKE_MODULE_PATH ${ECM_MODULE_PATH})

include(KDEInstallDirs)
include(KDECMakeSettings)
include(KDECompilerSettings NO_POLICY_SCOPE)
include(ECMInstallIcons)
include(FeatureSummary)

find_package(Qt6 REQUIRED COMPONENTS Core Gui Widgets)
find_package(OpenSSL REQUIRED)
find_package(KF6 REQUIRED COMPONENTS
    CoreAddons
    DBusAddons
    I18n
    XmlGui
    WidgetsAddons
    Wallet
    WindowSystem
    DocTools
)

configure_file(src/version.h.in ${CMAKE_BINARY_DIR}/version.h @ONLY)

add_executable(kdecrypt
    src/main.cpp
    src/mainwindow.cpp
    src/mainwindow.h
    src/decryptedfile.cpp
    src/decryptedfile.h
    src/gpgengine.cpp
    src/gpgengine.h
    src/settingsdialog.cpp
    src/settingsdialog.h
    src/keygendialog.cpp
    src/keygendialog.h
    src/encryptdialog.cpp
    src/encryptdialog.h
    src/walletmanager.cpp
    src/walletmanager.h
    src/cryptohelper.cpp
    src/cryptohelper.h
)

target_include_directories(kdecrypt PRIVATE ${CMAKE_BINARY_DIR})

target_link_libraries(kdecrypt PRIVATE
    Qt6::Core
    Qt6::Gui
    Qt6::Widgets
    KF6::CoreAddons
    KF6::DBusAddons
    KF6::I18n
    KF6::XmlGui
    KF6::WidgetsAddons
    KF6::Wallet
    KF6::WindowSystem
    OpenSSL::Crypto
)

kdoctools_create_handbook(doc/en/index.docbook INSTALL_DESTINATION ${KDE_INSTALL_DOCBUNDLEDIR}/en SUBDIR kdecrypt)
kdoctools_create_handbook(doc/pl/index.docbook INSTALL_DESTINATION ${KDE_INSTALL_DOCBUNDLEDIR}/pl SUBDIR kdecrypt)

ki18n_install(po)

install(TARGETS kdecrypt DESTINATION ${KDE_INSTALL_BINDIR})
install(FILES org.guidlab.kdecrypt.desktop DESTINATION ${KDE_INSTALL_APPDIR})
install(FILES kdecryptui.rc DESTINATION ${KDE_INSTALL_KXMLGUIDIR}/kdecrypt)
install(FILES org.guidlab.kdecrypt.metainfo.xml DESTINATION ${KDE_INSTALL_METAINFODIR})

ecm_install_icons(ICONS
    icons/16-apps-kdecrypt.png
    icons/22-apps-kdecrypt.png
    icons/32-apps-kdecrypt.png
    icons/48-apps-kdecrypt.png
    icons/64-apps-kdecrypt.png
    icons/128-apps-kdecrypt.png
    icons/256-apps-kdecrypt.png
    icons/512-apps-kdecrypt.png
    icons/sc-apps-kdecrypt.svg
    DESTINATION ${KDE_INSTALL_ICONDIR}
)

feature_summary(WHAT ALL FATAL_ON_MISSING_REQUIRED_PACKAGES)
