#!/usr/bin/env bash

check_exists() {
    command -v "$1" > /dev/null
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

run_jm_tests ()
{
    if [[ -z "${VIRTUAL_ENV}" ]]; then
        echo "Source JM virtualenv before running tests:

        \`source ./jmvenv/bin/activate\`"
        return 1
    fi
    jm_requirements="requirements/testing.txt"
    jm_source="${VIRTUAL_ENV}/.."
    export PKG_CONFIG_PATH="${PKG_CONFIG_PATH}:${VIRTUAL_ENV}/lib/pkgconfig"
    export LD_LIBRARY_PATH="${LD_LIBRARY_PATH}:${VIRTUAL_ENV}/lib"
    export C_INCLUDE_PATH="${C_INCLUDE_PATH}:${VIRTUAL_ENV}/include"

    pushd "${jm_source}"
    if ! sha256_verify 'ce3a4ddc777343645ccd06ca36233b5777e218ee89d887ef529ece86a917fc33' 'miniircd.tar.gz'; then
        http_get "https://github.com/JoinMarket-Org/miniircd/archive/master.tar.gz" "miniircd.tar.gz"
    fi
    if [[ ! -x ${jm_source}/miniircd/miniircd ]]; then
        rm -rf ./miniircd
        mkdir -p miniircd
        tar -xzf miniircd.tar.gz -C ./miniircd --strip-components=1
    fi
    if ! pip install -r "${jm_requirements}"; then
        echo "Packages in '${jm_requirements}' could not be installed. Exiting."
        return 1
    fi
    if [[ ! -L ./joinmarket.cfg && -e ./joinmarket.cfg ]]; then
        mv ./joinmarket.cfg ./joinmarket.cfg.bak
		echo "file 'joinmarket.cfg' moved to 'joinmarket.cfg.bak'"
    fi
    for dir in '/dev/shm' '/Volumes/ramdisk' '/tmp' "${jm_source}/test"; do
        if [[ -d "${dir}" && -r "${dir}" && -w "${dir}" && -x "${dir}" ]]; then
            jm_test_datadir="${dir}/jm_test_home/.bitcoin"
            break
        fi
    done
    if [[ -z "${jm_test_datadir}" ]]; then
        echo "No candidate directory for test files. Exiting."
        return 1
    fi
    [[ -f ./joinmarket.cfg ]] && unlink ./joinmarket.cfg
    ln -s ./test/regtest_joinmarket.cfg ./joinmarket.cfg
    orig_umask="$(umask -p)"
    umask 077
    rm -rf "${jm_test_datadir}"
    mkdir -p "${jm_test_datadir}"
    cp -f ./test/bitcoin.conf "${jm_test_datadir}/bitcoin.conf"
    ${orig_umask}
    echo "datadir=${jm_test_datadir}" >> "${jm_test_datadir}/bitcoin.conf"
    python -m pytest ${HAS_JOSH_K_SEAL_OF_APPROVAL+--cov=jmclient --cov=jmbitcoin --cov=jmbase --cov=jmdaemon --cov-report html} --btcpwd=123456abcdef --btcconf=${jm_test_datadir}/bitcoin.conf --btcuser=bitcoinrpc --nirc=2 -p no:warnings --ignore test/test_full_coinjoin.py
    local success="$?"
    [[ -f ./joinmarket.cfg ]] && unlink ./joinmarket.cfg
    if [ -f "${jm_test_datadir}/bitcoind.pid" ] && read bitcoind_pid <"${jm_test_datadir}/bitcoind.pid"; then
        kill -15 ${bitcoind_pid} || kill -9 ${bitcoind_pid}
    fi
    if [[ "${HAS_JOSH_K_SEAL_OF_APPROVAL}" == true ]] && (( ${success} != 0 )); then
        tail -100 "${jm_test_datadir}/regtest/debug.log"
        find "${jm_test_datadir}"
    else
        rm -rf "${jm_test_datadir}"
    fi
    return ${success:-1}
}
run_jm_tests
