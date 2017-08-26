#!/bin/bash

# jm_source="$PWD/.."
# jm_root="${jm_source}/jmvenv"
# jm_deps="${jm_source}/deps"

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

deb_deps_check ()
{
    apt-cache policy ${deb_deps[@]}
}

deb_deps_install ()
{
    deb_deps=( 'python-virtualenv' 'curl' 'python-dev' 'python-pip' 'build-essential' 'automake' 'pkg-config' 'libtool' )
    if ! deb_deps_check; then
        clear
        echo "
            sudo password required to run :

            \`apt-get install ${deb_deps[@]}\`
            "
        if ! sudo apt-get install ${deb_deps[@]}; then
            return 1
        fi
    fi
}

check_skip_build ()
{
    if ! mkdir "$1"; then
        read -p "Directory ${1} exists.  Remove and recreate?  (y/n)  " q
        if [[ "${q}" =~ Y|y ]]; then
            rm -rf "./${1}"
            return 1
        else
            echo "skipping ${1}..."
            return 0
        fi
    fi
    return 1
}

venv_setup ()
{
    if check_skip_build 'jmvenv'; then
        return 0
    fi
    virtualenv -p python2 jmvenv
}

openssl_get ()
{
    for file in "${openssl_lib_tar}" "${openssl_lib_sha}" "${openssl_lib_sig}"; do
        curl -L -O "${openssl_url}/${file}"
    done
    curl -L "${openssl_signer_key_url}" -o openssl_signer.key
}

openssl_build ()
{
    ./config shared --prefix="${jm_root}"
    make -j
    if ! make test; then
        return 1
    fi
}

openssl_install ()
{
    openssl_version='openssl-1.0.2l'
    openssl_lib_tar="${openssl_version}.tar.gz"
    openssl_lib_sha="${openssl_lib_tar}.sha256"
    openssl_lib_sig="${openssl_lib_tar}.asc"
    openssl_url='https://www.openssl.org/source'
    openssl_signer_key_url='https://pgp.mit.edu/pks/lookup?op=get&search=0xD9C4D26D0E604491'
    openssl_signer_key_id='2048R/D9C4D26D0E604491'
    openssl_root="${jm_deps}/openssl"

    if check_skip_build 'openssl'; then
        return 0
    fi
    pushd openssl
    openssl_get
    if ! grep $(sha256sum "${openssl_lib_tar}") "${openssl_lib_sha}"; then
        return 1
    fi
    if gpg_verify_key openssl_signer.key "${openssl_signer_key_id}"; then
        gpg_add_to_keyring openssl_signer.key
    else
        return 1
    fi
    if gpg_verify_sig "${openssl_lib_sig}"; then
        tar xaf "${openssl_lib_tar}"
    else
        return 1
    fi
    pushd "${openssl_version}"
    if openssl_build; then
        make install
    else
        return 1
    fi
    popd
    popd
}

# add '--disable-docs' to libffi ./configure so makeinfo isn't needed
# https://github.com/libffi/libffi/pull/190/commits/fa7a257113e2cfc963a0be9dca5d7b4c73999dcc
libffi_patch_disable_docs ()
{
    cat <<'EOF' > Makefile.am.patch
56c56,59
< info_TEXINFOS = doc/libffi.texi
---
> info_TEXINFOS =
> if BUILD_DOCS
> #info_TEXINFOS += doc/libffi.texi
> endif
EOF

    cat <<'EOF' > configure.ac.patch
545a546,552
> AC_ARG_ENABLE(docs,
>               AC_HELP_STRING([--disable-docs],
>                              [Disable building of docs (default: no)]),
>               [enable_docs=no],
>               [enable_docs=yes])
> AM_CONDITIONAL(BUILD_DOCS, [test x$enable_docs = xyes])
> 
EOF
    patch Makefile.am Makefile.am.patch
    patch configure.ac configure.ac.patch
}

libffi_build ()
{
    ./autogen.sh
    ./configure --disable-docs --enable-shared --prefix="${jm_root}"
    make -j
    if ! make check; then
        return 1
    fi
}

libffi_install ()
{
    libffi_version='libffi-3.2.1'
    libffi_lib_tar="v3.2.1.tar.gz"
    libffi_lib_sha='96d08dee6f262beea1a18ac9a3801f64018dc4521895e9198d029d6850febe23'
    libffi_url="https://github.com/libffi/libffi/archive"

    if check_skip_build 'libffi'; then
        return 0
    fi
    pushd libffi
    curl -L -O "${libffi_url}/${libffi_lib_tar}"
    if sha256sum -c <<<"${libffi_lib_sha}  ${libffi_lib_tar}"; then
        tar xaf "${libffi_lib_tar}"
    else
        return 1
    fi
    pushd "${libffi_version}"
    if ! libffi_patch_disable_docs; then
        return 1
    fi
    if libffi_build; then
        make install
    else
        return 1
    fi
    popd
    popd
}

libsodium_get ()
{
    for file in "${sodium_lib_tar}" "${sodium_lib_sig}"; do
        curl -L -O "${sodium_url}/${file}"
    done
    curl -L "${sodium_signer_key_url}" -o libsodium_signer.key
}

libsodium_build ()
{
    ./autogen.sh
    ./configure --enable-shared --prefix="${jm_root}" 
    make -j
    if ! make check; then
        return 1
    fi
}

libsodium_install ()
{
    sodium_version='libsodium-1.0.13'
    sodium_lib_tar="${sodium_version}.tar.gz"
    sodium_lib_sig="${sodium_lib_tar}.sig"
    sodium_url='https://download.libsodium.org/libsodium/releases'
    sodium_signer_key_url='https://pgp.mit.edu/pks/lookup?op=get&search=0x210627AABA709FE1'
    sodium_signer_key_id='4096R/62F25B592B6F76DA'

    if check_skip_build 'libsodium'; then
        return 0
    fi
    pushd libsodium
    libsodium_get
    if gpg_verify_key libsodium_signer.key "${sodium_signer_key_id}"; then
        gpg_add_to_keyring libsodium_signer.key
    else
        return 1
    fi
    if gpg_verify_sig "${sodium_lib_sig}"; then
        tar xaf "${sodium_lib_tar}"
    else
        return 1
    fi
    pushd "${sodium_version}"
    if libsodium_build; then
        make install
    else
        return 1
    fi
    popd
    popd
}

joinmarket_install ()
{
    jm_pkgs=( 'jmbase' 'jmdaemon' 'jmbitcoin' 'jmclient' )
    for pkg in ${jm_pkgs[@]}; do
        pushd "${pkg}"
        pip install .
        popd
    done
}

main ()
{
    jm_source="$PWD"
    jm_root="${jm_source}/jmvenv"
    jm_deps="${jm_source}/deps"
    export PKG_CONFIG_PATH="${PKG_CONFIG_PATH}:${jm_root}/lib/pkgconfig"

    if ! deb_deps_install; then
        echo "Dependecies could not be installed. Exiting."
        return 1
    fi
    if ! venv_setup; then
        echo "Joinmarket virtualenv could not be setup. Exiting."
    fi
    source "${jm_root}/bin/activate"
    mkdir -p deps
    pushd deps
    rm -f ./keyring.gpg
    if ! openssl_install; then
        echo "Openssl was not built. Exiting."
        return 1
    fi
    if ! libffi_install; then
        echo "Libffi was not built. Exiting."
        return 1
    fi
    if ! libsodium_install; then
        echo "Libsodium was not built. Exiting."
    fi
    popd
    if ! joinmarket_install; then
        echo "Joinmarket was not installed. Exiting."
    fi
    deactivate
    echo "Joinmarket successfully installed
    Before executing scripts or tests, run:

    \`source jmvenv/bin/activate\`
    
    from this directiry, to acticate virtualenv."
}
main
