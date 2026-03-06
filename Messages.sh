#!/bin/sh
# SPDX-FileCopyrightText: 2026 Guid <guid@guid.pl>
# SPDX-License-Identifier: GPL-3.0-or-later

$XGETTEXT $(find src -name '*.cpp' -o -name '*.h') -o $podir/kdecrypt.pot
