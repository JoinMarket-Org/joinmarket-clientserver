#!/bin/bash

run_jm_tests ()
{
    if [[ -z "${VIRTUAL_ENV}" ]]; then
        echo "Source JM virtualenv before running tests:

        \`source ./jmvenv/bin/activate\`"
        return 1
    fi
    jm_source="${VIRTUAL_ENV}/.."

    pushd "${jm_source}"
    git clone git://github.com/Joinmarket-Org/miniircd.git
    if ! pip install -r ./requirements-dev.txt; then
        echo "Packages in 'requirements-dev.txt' could not be installed. Exiting."
        return 1
    fi
    if [[ ! -L ./joinmarket.cfg && -e ./joinmarket.cfg ]]; then
        mv ./joinmarket.cfg ./joinmarket.cfg.bak
		echo "file 'joinmarket.cfg' moved to 'joinmarket.cfg.bak'"
    fi
    for dir in '/dev/shm' '/tmp' "${jm_source}/test"; do
        if [[ -d "${dir}" && -r "${dir}" ]]; then
            jm_test_datadir="${dir}/jm_test_home/.bitcoin"
            break
        fi
    done
    if [[ -z "${jm_test_datadir}" ]]; then
        echo "No candidate directory for test files. Exiting."
        return 1
    fi
    unlink ./joinmarket.cfg
    ln -s ./test/regtest_joinmarket.cfg ./joinmarket.cfg
    orig_umask="$(umask -p)"
    umask 077
    rm -rf "${jm_test_datadir}"
    mkdir -p "${jm_test_datadir}"
    cp -f ./test/bitcoin.conf "${jm_test_datadir}/bitcoin.conf"
    ${orig_umask}
    echo "datadir=${jm_test_datadir}" >> "${jm_test_datadir}/bitcoin.conf"
    python -m py.test --cov=jmclient --cov=jmbitcoin --cov=jmbase --cov=jmdaemon --cov-report html --btcpwd=123456abcdef --btcconf=${jm_test_datadir}/bitcoin.conf --btcuser=bitcoinrpc --nirc=2 --ignore jmclient/test/test_wallets.py --ignore test/test_segwit.py
    unlink ./joinmarket.cfg
    if read bitcoind_pid <"${jm_test_datadir}/bitcoind.pid"; then
        pkill -15 ${bitcoind_pid} || pkill -9 ${bitcoind_pid}
    fi
    rm -rf "${jm_test_datadir}"
}
run_jm_tests
