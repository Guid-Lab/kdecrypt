# Contributing

Thanks for your interest in contributing to KDecrypt!

## Getting Started

1. Fork the repository
2. Clone your fork and create a branch
3. Build the project (see below)
4. Make your changes
5. Submit a pull request

## Building

```bash
mkdir build && cd build
cmake .. -DCMAKE_INSTALL_PREFIX=/usr
make
```

### Dependencies

- KDE Frameworks 6 (KIO, KWidgetsAddons, KXmlGui, KI18n, KCrash)
- Qt 6
- CMake 3.16+

## Reporting Issues

- Use GitHub Issues for bug reports and feature requests
- Include steps to reproduce for bugs
- Include your distro, KDE/Qt versions
- Check existing issues before creating a new one

## Pull Requests

- Keep changes focused and minimal
- Follow existing code style
- Update translations if adding user-visible strings
