#!/bin/bash

# A script to build a Windows executable for JoinmarketQt.
#
# credit to Electrum: https://github.com/spesmilo/electrum/blob/121be4cde6a48d1828ebdb409bdd714a3f1fead1/contrib/build-wine/prepare-wine.sh
# for a large number of the important details in this script, and most especially the PyInstaller build.
# Other things were from our own installation script, and a lot of experimentation.
#
# THIS IS CURRENTLY IN A VERY RAW UNPOLISHED STATE!
# (but it is not for users; if you use it you are on your own.)
# TODO improve it!

set -e

function download_if_not_exist() {
    local file_name=$1 url=$2
    if [ ! -e $file_name ] ; then
    echo "calling wget with url:"
    echo ${url}
        wget -O $file_name "$url"
    fi
}

check_exists() {
    command -v "$1" > /dev/null
}

gpg_verify_key ()
{
    gpg --keyid-format long <"$1" | grep "$2"
}

gpg_add_to_keyring ()
{
    gpg --dearmor <"$1" >>"${jm_deps}/keyring.gpg"
}

gpg_verify_sig ()
{
    gpg --no-default-keyring --keyring "${jm_deps}/keyring.gpg" --verify "$1"
}

sha256_verify ()
{
    if [[ "$(uname)" == "Darwin" ]]; then
        shasum -a 256 -c <<<"$1  $2"
        return "$?"
    else
        sha256sum -c <<<"$1  $2"
        return "$?"
    fi
}

# http_get url filename
http_get ()
{
    if check_exists curl; then
        curl --retry 5 -L "$1" -o "$2"
    elif check_exists wget; then
        wget "$1" -O "$2"
    else
        echo "Neither curl nor wget present; please install one of them using your OS package manager."
        kill $$
    fi
}

dep_get ()
{
    pkg_name="$1" pkg_hash="$2" pkg_url="$3"

    pushd cache
    if ! sha256_verify "${pkg_hash}" "${pkg_name}"; then
        http_get "${pkg_url}/${pkg_name}" "${pkg_name}"
    fi
    if ! sha256_verify "${pkg_hash}" "${pkg_name}"; then
        return 1
    fi
    tar -xzf "${pkg_name}" -C ../
    popd
}

here="$(dirname "$(readlink -e "$0")")"
test -n "$here" -a -d "$here" || exit

export CONTRIB="$here/.."
export PROJECT_ROOT="$CONTRIB/.."
export CACHEDIR="$here/.cache"
export PIP_CACHE_DIR="$CACHEDIR/pip_cache"

export BUILD_TYPE="wine"
export GCC_TRIPLET_HOST="i686-w64-mingw32"
export GCC_TRIPLET_BUILD="x86_64-pc-linux-gnu"
export GCC_STRIP_BINARIES="1"

# use the above as AUTOCONF_FLAGS to target a win32 build:
if [ -n "$GCC_TRIPLET_HOST" ] ; then
    export AUTOCONF_FLAGS="$AUTOCONF_FLAGS --host=$GCC_TRIPLET_HOST"
fi
if [ -n "$GCC_TRIPLET_BUILD" ] ; then
    export AUTOCONF_FLAGS="$AUTOCONF_FLAGS --build=$GCC_TRIPLET_BUILD"
fi

echo "Clearing $here/build and $here/dist..."
rm "$here"/build/* -rf
rm "$here"/dist/* -rf

mkdir -p "$CACHEDIR" "$PIP_CACHE_DIR"

PYINSTALLER_REPO="https://github.com/SomberNight/pyinstaller.git"
PYINSTALLER_COMMIT="e934539374e30d1500fcdbe8e4eb0860413935b2"
# ^ tag 3.6, plus a custom commit that fixes cross-compilation with MinGW
# (see Electrum docs)

# using this version to match Electrum's pyinstaller workflow:
PYTHON_VERSION=3.7.7

export WINEPREFIX=~/.wine
export WINEDEBUG=-all

PYTHON_FOLDER="python3"
PYHOME="c:/$PYTHON_FOLDER"
PYTHON="wine $PYHOME/python.exe -OO -B"


echo "Booting wine."
wine 'wineboot'


cd "$CACHEDIR"
mkdir -p $WINEPREFIX/drive_c/tmp

echo "Installing Python."

wget -N -c "https://www.python.org/static/files/pubkeys.txt"
gpg --import pubkeys.txt
rm pubkeys.txt


PYTHON_DOWNLOADS="$CACHEDIR/python$PYTHON_VERSION"
mkdir -p "$PYTHON_DOWNLOADS"
for msifile in core dev exe lib pip tools; do
    echo "Installing $msifile..."
    download_if_not_exist "$PYTHON_DOWNLOADS/${msifile}.msi" "https://www.python.org/ftp/python/$PYTHON_VERSION/win32/${msifile}.msi"
    download_if_not_exist "$PYTHON_DOWNLOADS/${msifile}.msi.asc" "https://www.python.org/ftp/python/$PYTHON_VERSION/win32/${msifile}.msi.asc"
    gpg --verify "$PYTHON_DOWNLOADS/${msifile}.msi.asc" "$PYTHON_DOWNLOADS/${msifile}.msi"
    wine msiexec /i "$PYTHON_DOWNLOADS/${msifile}.msi" /qb TARGETDIR=$PYHOME
done

echo "Installing build dependencies."
$PYTHON -m pip install pywin32
$PYTHON -m pip install --no-dependencies --no-warn-script-location -r "$CONTRIB"/requirements/wine-build.txt

# BUILD DLLs:
# obviously the runner of the script will need build dependencies installed on their OS; TODO add this.
# note that libsodium build ought to be possible,
# but there are problems with libgcc not being linked statically
# if using the same AUTOCONF_FLAGS as for libsecp256k1 below.
# For now we use the NuGet package and verify the hash (details below).
libsodium_install ()
{
    sodium_pkg_hash="f6eb579b442ffae690efaf46da310eff5302a91923cb48f1554af93066a11f97"
    sodium_version_num="1.0.18"
    echo "${sodium_version_num}"
    sodium_version="libsodium-${sodium_version_num}"
    echo "${sodium_version}"
    download_if_not_exist "./${sodium_version}.zip" "https://www.nuget.org/api/v2/package/libsodium/${sodium_version_num}"
    # hash check:
    if ! sha256_verify "${sodium_pkg_hash}" "${sodium_version}.zip"; then
        return 1
    fi
    # TODO:
    # (It will require installation of package 'nuget' on OS):
    # note there is currently not a signature verification step, see:
    # https://docs.microsoft.com/en-us/nuget/reference/cli-reference/cli-ref-verify
    # quote:
    # "Verification of signed packages is not yet supported in .NET Core, under Mono, or on non-Windows platforms."

    rm -rf $sodium_version
    unzip ${sodium_version}.zip -d $sodium_version
    # for some weird reason these files have zero permissions:
    chmod 755 "${sodium_version}/runtimes/win-x86/native/libsodium.dll"
}

libsecp256k1_build()
{
    make clean
    echo "libsecp256k1_la_LDFLAGS = -no-undefined" >> Makefile.am
    echo "LDFLAGS = -no-undefined" >> Makefile.am
    ./autogen.sh
    ./configure \
    $AUTOCONF_FLAGS \
    --enable-module-recovery \
    --disable-jni \
    --prefix "${jm_root}" \
    --enable-experimental \
    --enable-module-ecdh \
    --disable-benchmark \
    --disable-tests \
    --disable-exhaustive-tests \
    --disable-static \
    --enable-shared
    make
    if ! make check; then
        return 1
    fi
}


libsecp256k1_install()
{
    secp256k1_lib_tar='0d9540b13ffcd7cd44cc361b8744b93d88aa76ba'
    secp256k1_lib_sha="0803d2dddbf6dd702c379118f066f638bcef6b07eea959f12d31ad2f4721fbe1"
    secp256k1_lib_url='https://github.com/bitcoin-core/secp256k1/archive'
    if ! dep_get "${secp256k1_lib_tar}.tar.gz" "${secp256k1_lib_sha}" "${secp256k1_lib_url}"; then
        return 1
    fi
    pushd "secp256k1-${secp256k1_lib_tar}"
    if libsecp256k1_build; then
	echo "libsecp256k1 dll build for Windows OK"
    else
        echo "libsecp256k1 dll build failed."
        return 1
    fi
    popd
}

main ()
{
    jm_source="$PWD"
    jm_root="${jm_source}/jmvenv"
    jm_deps="${jm_source}/deps"
    export PKG_CONFIG_PATH="${jm_root}/lib/pkgconfig:${PKG_CONFIG_PATH}"
    export LD_LIBRARY_PATH="${jm_root}/lib:${LD_LIBRARY_PATH}"
    export C_INCLUDE_PATH="${jm_root}/include:${C_INCLUDE_PATH}"
    export MAKEFLAGS='-j'

    mkdir -p "deps/cache"
    pushd deps
    if ! libsecp256k1_install; then
        echo "libsecp256k1 was not built. Exiting."
        return 1
    fi
    if ! libsodium_install; then
        echo "Libsodium was not built. Exiting."
        return 1
    fi
    popd
}

main ${@}

# copy built dlls to windows drive:
cp "deps/secp256k1-${secp256k1_lib_tar}/.libs/libsecp256k1-0.dll" $WINEPREFIX/drive_c/tmp/ || fail "Could not copy libsecp to its destination"
cp "deps/${sodium_version}/runtimes/win-x86/native/libsodium.dll" $WINEPREFIX/drive_c/tmp/libsodium.dll || fail "Could not copy libsodium to its destination"
echo "Building PyInstaller."
# we build our own PyInstaller boot loader as the default one has high
# anti-virus false positives
(
    cd "$CACHEDIR"
    rm -rf pyinstaller
    mkdir pyinstaller
    cd pyinstaller
    # Shallow clone
    git init
    git remote add origin $PYINSTALLER_REPO
    git fetch --depth 1 origin $PYINSTALLER_COMMIT
    git checkout -b pinned "${PYINSTALLER_COMMIT}^{commit}"
    rm -fv PyInstaller/bootloader/Windows-*/run*.exe || true

    pushd bootloader
    # cross-compile to Windows using host python
    python3 ./waf all  CC=i686-w64-mingw32-gcc CFLAGS="-static -Wno-dangling-else -Wno-error=unused-value"
    popd
    # sanity check bootloader is there:
    [[ -e PyInstaller/bootloader/Windows-32bit/runw.exe ]] || fail "Could not find runw.exe in target dir!"
) || fail "PyInstaller build failed"
echo "Installing PyInstaller."
#$PYTHON -m pip install --no-dependencies --no-warn-script-location ./pyinstaller

echo "Wine is configured."

cd "$CONTRIB"
$PYTHON -m pip install  -r requirements/gui.txt

# TODO : Can this step be made non-manually on the Wine instance?:
# won't run without:
# https://visualstudio.microsoft.com/downloads/
# https://aka.ms/vs/16/release/VC_redist.x86.exe
# need x86
# need MSVCP140_1.DLL

# build the final executable:
cd $here
echo "Running pyinstaller..."
wine "$PYHOME/scripts/pyinstaller.exe" --noconfirm --ascii --clean -w joinmarket-qt.spec

