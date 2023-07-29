#!/usr/bin/env bash

cd "$(dirname "$0")" || exit

check_exists()
{
    command -v "$1" > /dev/null
}

# This may be overriden by --python/-p option.
python="python3"

# This is needed for systems where GNU is not the default make, like FreeBSD.
if check_exists gmake; then
    make="gmake"
else
    make="make"
fi

num_cores()
{
    ${python} -c 'import multiprocessing as mp; print(mp.cpu_count())'
}

sha256_verify ()
{
    if [[ "$(uname)" == "Darwin" ]]; then
        shasum -a 256 -c <<<"$1  $2"
        return "$?"
    elif [[ "$(uname)" == "FreeBSD" ]]; then
        sha256 -c "$1" "$2"
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

gpg_verify ()
{
    if [[ $no_gpg_validation != 1 ]]; then
        if ! check_exists gpg; then
            echo "GPG not installed, cannot verify release signatures; install gpg or use --no-gpg-validation."
            kill $$
        fi
        gpg --import "$1"
        gpg --verify "$2" || kill $$
    fi
}

deps_install ()
{
    debian_deps=( \
        'curl' \
        'build-essential' \
        'automake' \
        'pkg-config' \
        'libtool' \
        'python3-dev' \
        'python3-pip' \
        'python3-setuptools' \
        'python3-venv' \
        'libltdl-dev' )

    if [ "$with_sudo" == 1 ]; then debian_deps+=("sudo"); fi

    darwin_deps=( \
        'automake' \
        'libtool' )

    if ! is_python3; then
        echo "Python 2 is no longer supported. Please use a compatible Python 3 version."
        return 1
    fi

    if [[ ${use_os_deps_check} != '1' ]]; then
        echo "Checking OS package manager's dependencies disabled. Trying to build."
        return 0
    elif [[ ${install_os} == 'debian' ]]; then
        deb_deps_install "${debian_deps[@]}"
        return "$?"
    elif [[ ${install_os} == 'darwin' ]]; then
        dar_deps_install "${darwin_deps[@]}"
        return "$?"
    else
        echo "OS can not be determined. Trying to build."
        return 0
    fi
}

tor_deps_install ()
{
    debian_deps=( \
        'libevent-dev' \
        'libssl-dev' \
        'zlib1g-dev' )

    darwin_deps=( \
        'libevent' \
        'zlib' )

    if [[ ${use_os_deps_check} != '1' ]]; then
        return 0
    elif [[ ${install_os} == 'debian' ]]; then
        deb_deps_install "${debian_deps[@]}"
        return "$?"
    elif [[ ${install_os} == 'darwin' ]]; then
        dar_deps_install "${darwin_deps[@]}"
        return "$?"
    else
        return 0
    fi
}

deb_deps_check ()
{
    apt-cache policy "${deb_deps[@]}" | grep "Installed.*none"
}

deb_deps_install ()
{
    deb_deps=( "${@}" )
    if deb_deps_check; then
        clear
        sudo_command=''
        if [ "$with_sudo" == 1 ]; then
            echo "
                sudo password required to run :

                \`apt-get install ${deb_deps[*]}\`
                "
            sudo_command="sudo"
        fi

        if ! $sudo_command apt-get install -y --no-install-recommends "${deb_deps[@]}"; then
              return 1
        fi
    fi
}

dar_deps_install ()
{
    dar_deps=( "${@}" )
    if ! brew install "${dar_deps[@]}"; then
        return 1
    fi
}

check_skip_build ()
{
    if [[ ${reinstall} == false ]] && [[ -d "$1" ]]; then
        read -r -n 1 -p "Directory ${1} exists.  Remove and recreate? (y/N) " q
        echo ""
        if [[ "${q}" =~ Y|y ]]; then
            rm -rf "./${1}"
            mkdir -p "./${1}"
            return 1
        else
            echo "skipping ${1}..."
            return 0
        fi
    fi
    return 1
}

upgrade_setuptools ()
{
    pip install --upgrade pip
    pip install --upgrade setuptools
}

venv_setup ()
{
    if check_skip_build 'jmvenv'; then
        return 0
    else
        reinstall='true'
    fi
    "${python}" -m venv "${jm_source}/jmvenv" || return 1
    # shellcheck source=/dev/null
    source "${jm_source}/jmvenv/bin/activate" || return 1
    upgrade_setuptools
    deactivate
}

dep_get ()
{
    pkg_name="$1" pkg_hash="$2" pkg_url="$3"
    pkg_pubkeys="$4" pkg_sig="$5" pkg_hash_file="$6" pkg_hash_file_sig="$7"

    pushd cache || return 1
    if [ ! -f "${pkg_name}" ] || ! sha256_verify "${pkg_hash}" "${pkg_name}"; then
        http_get "${pkg_url}/${pkg_name}" "${pkg_name}"
    fi
    if ! sha256_verify "${pkg_hash}" "${pkg_name}"; then
        return 1
    fi
    if [[ -n "${pkg_hash_file}" ]]; then
        http_get "${pkg_url}/${pkg_hash_file}" "${pkg_hash_file}"
        if [[ -n "${pkg_hash_file_sig}" ]]; then
            http_get "${pkg_url}/${pkg_hash_file_sig}" "${pkg_hash_file_sig}"
            gpg_verify "../../pubkeys/third-party/${pkg_pubkeys}" "${pkg_hash_file_sig}"
        fi
        if ! grep -qs "${pkg_hash}" "${pkg_hash_file}"; then
            echo "Hash mismatch, ${pkg_hash} not in ${pkg_url}/${pkg_hash_file}!"
            return 1
        fi
    fi
    if [[ -n "${pkg_sig}" ]]; then
        http_get "${pkg_url}/${pkg_sig}" "${pkg_sig}"
        gpg_verify "../../pubkeys/third-party/${pkg_pubkeys}" "${pkg_sig}"
    fi
    tar -xzf "${pkg_name}" -C ../
    popd || return 1
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

    # autogen.sh is not happy when run from some directories, causing it
    # to create an ltmain.sh file in our ${jm_root} directory.  weird.
    # https://github.com/meetecho/janus-gateway/issues/290#issuecomment-125160739
    # https://github.com/meetecho/janus-gateway/commit/ac38cfdae7185f9061569b14809af4d4052da700
    cat <<'EOF' > autoreconf.patch
18a19
> AC_CONFIG_AUX_DIR([.])
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
    patch configure.ac autoreconf.patch
    patch configure.ac configure.ac.patch
}

libffi_build ()
{
    ./autogen.sh
    ./configure --disable-docs --enable-shared --prefix="${jm_root}"
    $make uninstall
    $make
    if ! $make check; then
        return 1
    fi
}

libffi_install ()
{
    libffi_version='libffi-3.2.1'
    libffi_lib_tar="v3.2.1.tar.gz"
    libffi_lib_sha='96d08dee6f262beea1a18ac9a3801f64018dc4521895e9198d029d6850febe23'
    libffi_url="https://github.com/libffi/libffi/archive"

    if check_skip_build "${libffi_version}"; then
        return 0
    fi
    if ! dep_get "${libffi_lib_tar}" "${libffi_lib_sha}" "${libffi_url}"; then
        return 1
    fi
    pushd "${libffi_version}" || return 1
    if ! libffi_patch_disable_docs; then
        return 1
    fi
    if libffi_build; then
        $make install
    else
        return 1
    fi
    popd || return 1
}

libsecp256k1_build()
{
    $make clean
    ./autogen.sh
    ./configure \
        --enable-module-recovery \
        --disable-jni \
        --prefix "${jm_root}" \
        --enable-experimental \
        --enable-module-ecdh \
        --enable-benchmark=no \
        MAKE=$make
    $make
    if [[ $use_secp_check == '1' ]]; then
        if ! $make check; then
            return 1
        fi
    else
        echo "Skipping libsecp256k1 tests."
    fi
}

libsecp256k1_install()
{
    secp256k1_version="0.4.0"
    secp256k1_lib_tar="v$secp256k1_version.tar.gz"
    secp256k1_lib_sha="d7c956606e7f52b7703fd2967cb31d2e21ec90c0b440ff1cc7c7d764a4092b98"
    secp256k1_lib_url='https://github.com/bitcoin-core/secp256k1/archive/refs/tags'
    if ! dep_get "${secp256k1_lib_tar}" "${secp256k1_lib_sha}" "${secp256k1_lib_url}"; then
        return 1
    fi
    pushd "secp256k1-$secp256k1_version" || return 1
    if libsecp256k1_build; then
        $make install
    else
        return 1
    fi
    popd || return 1
}

libsodium_build ()
{
    $make uninstall
    $make distclean
    ./autogen.sh
    ./configure \
        --enable-minimal \
        --enable-shared \
        --prefix="${jm_root}"
    $make uninstall
    $make
    if ! $make check; then
        return 1
    fi
}

libsodium_install ()
{
    sodium_version='libsodium-1.0.18'
    sodium_lib_tar="${sodium_version}.tar.gz"
    sodium_lib_sha='6f504490b342a4f8a4c4a02fc9b866cbef8622d5df4e5452b46be121e46636c1'
    sodium_url='https://download.libsodium.org/libsodium/releases'
    sodium_pubkeys='libsodium.asc'

    if check_skip_build "${sodium_version}"; then
        return 0
    fi
    if ! dep_get "${sodium_lib_tar}" "${sodium_lib_sha}" "${sodium_url}" "${sodium_pubkeys}" "${sodium_lib_tar}.sig"; then
        return 1
    fi
    pushd "${sodium_version}" || return 1
    if libsodium_build; then
        $make install
    else
        return 1
    fi
    popd || return 1
}

tor_root ()
{
    # jm_root will be empty for --docker-install,
    # sys.prefix defaults to /usr/local
    if [[ -n "$jm_root" ]]; then
        echo "$jm_root"
    else
        echo "/usr/local"
    fi
}

tor_build ()
{
    $make uninstall
    $make distclean
    ./configure \
        --disable-system-torrc \
        --disable-seccomp \
        --disable-libscrypt \
        --disable-module-relay \
        --disable-lzma \
        --disable-zstd \
        --disable-asciidoc \
        --disable-manpage \
        --disable-html-manual \
        --prefix="$(tor_root)"
    $make
    if ! $make check; then
        return 1
    fi
}

tor_install ()
{
    tor_version='tor-0.4.8.7'
    tor_tar="${tor_version}.tar.gz"
    tor_sha='b20d2b9c74db28a00c07f090ee5b0241b2b684f3afdecccc6b8008931c557491'
    tor_url='https://dist.torproject.org'
    tor_pubkeys='Tor.asc'

    if ! dep_get "${tor_tar}" "${tor_sha}" "${tor_url}" "${tor_pubkeys}" "" "${tor_tar}.sha256sum" "${tor_tar}.sha256sum.asc"; then
        return 1
    fi
    pushd "${tor_version}" || return 1
    if tor_build; then
        $make install
        echo "# Default JoinMarket Tor configuration
Log warn stderr
SOCKSPort 9050 IsolateDestAddr IsolateDestPort
ControlPort 9051
CookieAuthentication 1
        " > "$(tor_root)/etc/tor/torrc"
    else
        return 1
    fi
    popd || return 1
}

joinmarket_install ()
{
    reqs='services'

    if [[ ${with_qt} == "1" ]]; then
        reqs='gui'
    fi
    if [[ ${develop} == "1" ]]; then
        reqs+=',test'
    fi

    if [ "$with_jmvenv" == 1 ]; then pip_command=pip; else pip_command=pip3; fi
    $pip_command install -e ".[${reqs}]" || return 1

    if [[ ${with_qt} == "1" ]]; then
        if [[ -d ~/.local/share/icons ]] && [[ -d ~/.local/share/applications ]]; then
            echo "Installing XDG desktop entry"
            cp -f "$(dirname "$0")/docs/images/joinmarket_logo.png" \
                ~/.local/share/icons/
            sed "s/\\\$JMHOME/$(dirname "$(realpath "$0")" | sed 's/\//\\\//g')/" \
                "$(dirname "$0")/joinmarket-qt.desktop" > \
                    ~/.local/share/applications/joinmarket-qt.desktop
        fi
    fi
}

parse_flags ()
{
    while :; do
        case $1 in
            --develop)
                # editable install is currently always on
                # option solely triggers test dependencies installation for now
                develop='1'
                ;;
            --disable-os-deps-check)
                use_os_deps_check='0'
                ;;
            --disable-secp-check)
                use_secp_check='0'
                ;;
            --no-gpg-validation)
                no_gpg_validation='1'
                ;;
            -p|--python)
                if [[ "$2" ]]; then
                    python="$2"
                    shift
                else
                    echo 'ERROR: "--python" requires a non-empty option argument.'
                    return 1
                fi
                ;;
            --python=?*)
                python="${1#*=}"
                ;;
            --python=)
                echo 'ERROR: "--python" requires a non-empty option argument.'
                return 1
                ;;
            --with-local-tor)
                build_local_tor='1'
                ;;
            --with-qt)
                with_qt='1'
                ;;
            --without-qt)
                with_qt='0'
                ;;
            --docker-install)
                with_sudo='0'
                with_jmvenv='0'
                ;;
            "")
                break
                ;;
            *)
                if [[ $1 != '-h' ]] && [[ $1 != '--help' ]]; then
                    echo "Invalid option $1"
                fi
                echo "
Usage: ${0} [options]

Options:

--develop                   code remains editable in place (currently always enabled)
--disable-os-deps-check     skip OS package manager's dependency check
--disable-secp-check        do not run libsecp256k1 tests (default is to run them)
--docker-install            system wide install as root for minimal Docker installs
--no-gpg-validation         disable GPG key validation for dependencies
--python, -p                python version (only python3 versions are supported)
--with-local-tor            build Tor locally and autostart when needed
--with-qt                   build the Qt GUI
--without-qt                don't build the Qt GUI
"
                return 1
                ;;
        esac
        shift
    done

    if [[ ${with_qt} == '' ]]; then
        read -r -n 1 -p "
        INFO: Joinmarket-Qt for GUI Taker and Tumbler modes is available.
        Install Qt dependencies (~160mb)? (y/N) "
        echo ""
        if [[ ${REPLY} =~ y|Y ]]; then
            echo "Building Qt GUI"
            with_qt='1'
        else
            echo "Not building Qt GUI"
        fi
    fi
}

os_is_deb ()
{
    ( which apt-get && which dpkg-query ) 2>/dev/null 1>&2
}

os_is_dar ()
{
    [[ "$(uname)" == "Darwin" ]]
}

is_python3 ()
{
    if [[ ${python} == python3* ]]; then
        return 0
    fi
    if [[ ${python} == python2* ]]; then
        return 1
    fi
    ${python} -c 'import sys; sys.exit(0) if sys.version_info >= (3,0) else sys.exit(1)'
}

install_get_os ()
{
    if os_is_deb; then
        echo 'debian'
    elif os_is_dar; then
        echo 'darwin'
    else
        echo 'unknown'
    fi
}

main ()
{
    # flags
    build_local_tor=''
    no_gpg_validation=''
    use_os_deps_check='1'
    use_secp_check='1'
    with_qt=''
    with_jmvenv='1'
    with_sudo='1'
    reinstall='false'
    if ! parse_flags "${@}"; then
        return 1
    fi

    jm_source="$PWD"
    if [ "$with_jmvenv" == 1 ]; then
        jm_root="${jm_source}/jmvenv"
        export PKG_CONFIG_PATH="${jm_root}/lib/pkgconfig:${PKG_CONFIG_PATH}"
        export LD_LIBRARY_PATH="${jm_root}/lib:${LD_LIBRARY_PATH}"
        export C_INCLUDE_PATH="${jm_root}/include:${C_INCLUDE_PATH}"
    else
        jm_root=""
    fi

    # os check
    install_os="$( install_get_os )"

    if ! deps_install; then
        echo "Dependecies could not be installed. Exiting."
        return 1
    fi

    MAKEFLAGS="-j $(num_cores)" && export MAKEFLAGS

    if [ "$with_jmvenv" == 1 ]; then
        if ! venv_setup; then
            echo "Joinmarket Python virtual environment could not be setup. Exiting."
            return 1
        fi
        # shellcheck source=/dev/null
        source "${jm_root}/bin/activate"
    else
        upgrade_setuptools
    fi
    if [[ ${build_local_tor} == "1" ]]; then
        if ! tor_deps_install; then
            echo "Tor dependencies could not be installed. Exiting."
            return 1
        fi
    fi
    mkdir -p "deps/cache"
    pushd deps || return 1
    if ! libsecp256k1_install; then
        echo "libsecp256k1 was not built. Exiting."
        return 1
    fi
    if ! libffi_install; then
        echo "Libffi was not built. Exiting."
        return 1
    fi
    if ! libsodium_install; then
        echo "Libsodium was not built. Exiting."
        return 1
    fi
    if [[ ${build_local_tor} == "1" ]]; then
        if ! tor_install; then
            echo "Building local Tor was requested, but not built. Exiting."
            return 1
        fi
    fi
    popd || return 1
    if ! joinmarket_install; then
        echo "Joinmarket was not installed. Exiting."
        if [ "$with_jmvenv" == 1 ]; then deactivate; fi
        return 1
    fi
    if [ "$with_jmvenv" == 1 ]; then
        deactivate
        echo "Joinmarket successfully installed
        Before executing scripts or tests, run:

        \`source jmvenv/bin/activate\`

        from this directory, to activate the virtual environment."
    fi
}
main "${@}"
