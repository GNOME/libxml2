pacman --noconfirm -Syu
pacman --noconfirm -S --needed `
    ${Env:MINGW_PACKAGE_PREFIX}cmake `
    ${Env:MINGW_PACKAGE_PREFIX}libiconv `
    ${Env:MINGW_PACKAGE_PREFIX}ninja `
    ${Env:MINGW_PACKAGE_PREFIX}python `
    ${Env:MINGW_PACKAGE_PREFIX}xz `
    ${Env:MINGW_PACKAGE_PREFIX}zlib
