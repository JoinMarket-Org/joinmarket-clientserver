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

parse_flags ()
{
    while :; do
        case $1 in
            -c|--btcconf)
                if [[ "$2" ]]; then
                    btcconf="$2"
                    shift
                else
                    echo 'ERROR: "--btcconf" requires a non-empty option argument.'
                    return 1
                fi
                ;;
            --btcconf=?*)
                btcconf="${1#*=}"
                ;;
            --btcconf=)
                echo 'ERROR: "--btcconf" requires a non-empty option argument.'
                return 1
                ;;
            -p|--btcpwd)
                if [[ "$2" ]]; then
                    btcpwd="$2"
                    shift
                else
                    echo 'ERROR: "--btcpwd" requires a non-empty option argument.'
                    return 1
                fi
                ;;
            --btcpwd=?*)
                btcpwd="${1#*=}"
                ;;
            --btcpwd=)
                echo 'ERROR: "--btcpwd" requires a non-empty option argument.'
                return 1
                ;;
            -r|--btcroot)
                if [[ "$2" ]]; then
                    btcroot="$2"
                    shift
                else
                    echo 'ERROR: "--btcroot" requires a non-empty option argument.'
                    return 1
                fi
                ;;
            --btcroot=?*)
                btcroot="${1#*=}"
                ;;
            --btcroot=)
                echo 'ERROR: "--btcroot" requires a non-empty option argument.'
                return 1
                ;;
            -u|--btcuser)
                if [[ "$2" ]]; then
                    btcuser="$2"
                    shift
                else
                    echo 'ERROR: "--btcuser" requires a non-empty option argument.'
                    return 1
                fi
                ;;
            --btcuser=?*)
                btcuser="${1#*=}"
                ;;
            --btcuser=)
                echo 'ERROR: "--btcuser" requires a non-empty option argument.'
                return 1
                ;;
            -i|--nirc)
                if [[ "$2" ]]; then
                    nirc="$2"
                    shift
                else
                    echo 'ERROR: "--nirc" requires a non-empty option argument.'
                    return 1
                fi
                ;;
            --nirc=?*)
                btcconf="${1#*=}"
                ;;
            --nirc=)
                echo 'ERROR: "--nirc" requires a non-empty option argument.'
                return 1
                ;;
            -v|--verbose)
                verbose_output=1
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

--btcconf, -c   the fully qualified path to the location of the bitcoin
                configuration file you use for testing, e.g.
                /home/user/.bitcoin/bitcoin.conf
--btcpwd, -p    the RPC password for your test bitcoin instance
--btcroot, -r   the fully qualified path to the directory containing the
                bitcoin binaries, e.g. /home/user/bitcoin/bin/
--btcuser, -u   the RPC username for your test bitcoin instance (default: $btcuser)
--nirc, -i      the number of local miniircd instances (default: $nirc)
--verbose, -v   verbose output
"
                exit 1
                ;;
        esac
        shift
    done
}

run_jm_tests ()
{
    verbose_output=0
    btcconf=""
    btcroot=""
    btcuser="bitcoinrpc"
    btcpwd="123456abcdef"
    nirc="2"
    if ! parse_flags "${@}"; then
        return 1
    fi

    additional_pytest_flags=""
    if [[ $verbose_output == 1 ]]; then
        additional_pytest_flags="-vv"
    fi

    if [[ -z "${VIRTUAL_ENV}" ]]; then
        echo "Source JM virtual environment before running tests:

        \`source ./jmvenv/bin/activate\`"
        return 1
    fi
    jm_source="${VIRTUAL_ENV}/.."

    pushd "${jm_source}" || return 1
    if [ ! -f 'miniircd.tar.gz' ] || ! sha256_verify 'ce3a4ddc777343645ccd06ca36233b5777e218ee89d887ef529ece86a917fc33' 'miniircd.tar.gz'; then
        http_get "https://github.com/JoinMarket-Org/miniircd/archive/master.tar.gz" "miniircd.tar.gz"
    fi
    if [[ ! -x ${jm_source}/miniircd/miniircd ]]; then
        rm -rf ./miniircd
        mkdir -p miniircd
        tar -xzf miniircd.tar.gz -C ./miniircd --strip-components=1
    fi
    if [[ ! -L ./joinmarket.cfg && -e ./joinmarket.cfg ]]; then
        mv ./joinmarket.cfg ./joinmarket.cfg.bak
		echo "file 'joinmarket.cfg' moved to 'joinmarket.cfg.bak'"
    fi
    for dir in '/dev/shm' '/Volumes/ramdisk' '/tmp' "${jm_source}/test"; do
        if [[ -d "${dir}" && -r "${dir}" && -w "${dir}" && -x "${dir}" ]]; then
            jm_test_datadir="${dir}/jm_test_home-$(whoami)/.bitcoin"
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
    if [[ -z "$btcconf" ]]; then
        btcconf="${jm_test_datadir}/bitcoin.conf"
        cp -f ./test/bitcoin.conf "${jm_test_datadir}/bitcoin.conf"
        # Temporary hack until we support descriptor wallets.
        # https://github.com/JoinMarket-Org/joinmarket-clientserver/issues/1571
        if [[ -n $btcroot ]]; then
            bitcoind="$btcroot/bitcoind"
        else
            bitcoind="bitcoind"
        fi
        if [[ "$($bitcoind -version -datadir="${jm_test_datadir}" | grep -Eo 'v[0-9]+')" == "v26" ]]; then
            echo "deprecatedrpc=create_bdb" >> "${jm_test_datadir}/bitcoin.conf"
        fi
    fi
    ${orig_umask}
    echo "datadir=${jm_test_datadir}" >> "${jm_test_datadir}/bitcoin.conf"
    python -m pytest $additional_pytest_flags \
        ${HAS_JOSH_K_SEAL_OF_APPROVAL+--cov=jmclient --cov=jmbitcoin --cov=jmbase --cov=jmdaemon --cov-report html} \
        --btcconf="$btcconf" \
        --btcpwd="$btcpwd" \
        --btcroot="$btcroot" \
        --btcuser="$btcuser" \
        --nirc="$nirc" \
        -p no:warnings
    local success="$?"
    [[ -f ./joinmarket.cfg ]] && unlink ./joinmarket.cfg
    if [ -f "${jm_test_datadir}/bitcoind.pid" ] && read -r bitcoind_pid < "${jm_test_datadir}/bitcoind.pid"; then
        kill -15 "${bitcoind_pid}" || kill -9 "${bitcoind_pid}"
    fi
    if [[ "${HAS_JOSH_K_SEAL_OF_APPROVAL}" == true ]] && (( success != 0 )); then
        tail -100 "${jm_test_datadir}/regtest/debug.log"
        find "${jm_test_datadir}"
    else
        rm -rf "${jm_test_datadir}"
    fi
    return ${success:-1}
}
run_jm_tests "${@}"
