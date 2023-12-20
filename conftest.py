import os
import re
import subprocess
from shlex import split
from time import sleep
from typing import Any, Tuple

import pytest


def get_bitcoind_version(bitcoind_path: str) -> Tuple[int, int]:
    """
    This utility function returns the bitcoind version number
    as a tuple in the form (major, minor)
    """
    version = local_command(f'{bitcoind_path} -version')
    if version.returncode != 0:
        raise RuntimeError(version.stdout.decode('utf-8'))
    version_string = version.stdout.split(b'\n')[0]
    version_tuple = re.match(
        br'.*v(?P<major>\d+)\.(?P<minor>\d+)', version_string).groups()
    major, minor = map(lambda x: int(x), version_tuple)
    return major, minor


def local_command(command: str, bg: bool = False):
    """
    Execute command in a new process.
    """
    command = split(command)
    if bg:
        # using subprocess.PIPE seems to cause problems
        FNULL = open(os.devnull, 'w')
        return subprocess.Popen(command,
                                stdout=FNULL,
                                stderr=subprocess.STDOUT,
                                close_fds=True)
    # in case of foreground execution, we can use the output; if not
    # it doesn't matter
    return subprocess.run(command, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT)


def root_path() -> str:
    """
    Returns the directory in which this file is contained.
    """
    return os.path.dirname(os.path.realpath(__file__))


def btc_conf_test_path() -> str:
    """
    Returns default Bitcoin conf test path.
    """
    return os.path.join(root_path(), 'test/bitcoin.conf')


def pytest_addoption(parser: Any) -> None:
    """
    Pytest initialization hook to register argparse-style options.
    """
    parser.addoption("--btcroot", action="store", default='',
                     help="the fully qualified path to the directory containing " +
                          "the bitcoin binaries, e.g. /home/user/bitcoin/bin/")
    parser.addoption("--btcconf", action="store",
                     default=btc_conf_test_path(),
                     help="the fully qualified path to the location of the " +
                          "bitcoin configuration file you use for testing, e.g. " +
                          "/home/user/.bitcoin/bitcoin.conf")
    parser.addoption("--btcpwd",
                     action="store",
                     help="the RPC password for your test bitcoin instance")
    parser.addoption("--btcuser",
                     action="store",
                     default='bitcoinrpc',
                     help="the RPC username for your test bitcoin instance (default=bitcoinrpc)")
    parser.addoption("--nirc",
                     type="int",
                     action="store",
                     default=1,
                     help="the number of local miniircd instances")


@pytest.fixture(scope="session", autouse=True)
def setup_early_if_needed(request) -> None:
    """
    Make sure fixtures requested by test *modules* are executed first.
    I.e., like a dynamically set `autouse=True`.
    (By default, without `autouse=True`, they would run later at request time)
    Useful so that fixtures like `setup_regtest_bitcoind` can run *only* if
    we are planning to invoke a test that requires it, but still at startup time.
    """
    modules = set()
    # Loop through the collected tests
    for item in request.node.items:
        module = item.getparent(pytest.Module)
        if module in modules:
            continue
        modules.add(module)
        # Loop through each test module marker
        for marker in module.iter_markers('usefixtures'):
            # We know we are gonna need these fixtures, so we invoke them early
            for fixture in marker.args:
                request.getfixturevalue(fixture)


@pytest.fixture(scope="session")
def setup_miniircd(pytestconfig):
    """
    Setup miniircd and handle its clean up.
    """
    miniircd_procs = []
    cwd = os.getcwd()
    n_irc = pytestconfig.getoption("--nirc")
    miniircd_path = os.path.join(root_path(), 'miniircd', 'miniircd')
    # minor bug in miniircd (seems); need *full* unqualified path for motd file
    motd_path = os.path.join(cwd, 'miniircd', 'testmotd')
    for i in range(n_irc):
        command = f"{miniircd_path} --ports={16667 + i} --motd={motd_path}"
        miniircd_proc = local_command(command, bg=True)
        miniircd_procs.append(miniircd_proc)
    yield
    # didn't find a stop command in miniircd, so just kill
    for m in miniircd_procs:
        m.kill()


@pytest.fixture(scope="session")
def setup_regtest_bitcoind(pytestconfig):
    """
    Setup regtest bitcoind and handle its clean up.
    """
    conf = pytestconfig.getoption("--btcconf")
    rpcuser = pytestconfig.getoption("--btcuser")
    rpcpassword = pytestconfig.getoption("--btcpwd")
    bitcoin_path = pytestconfig.getoption("--btcroot")
    bitcoind_path = os.path.join(bitcoin_path, "bitcoind")
    bitcoincli_path = os.path.join(bitcoin_path, "bitcoin-cli")
    start_cmd = f'{bitcoind_path} -regtest -daemon -conf={conf}'
    stop_cmd = f'{bitcoincli_path} -regtest -rpcuser={rpcuser} -rpcpassword={rpcpassword} stop'

    # determine bitcoind version
    try:
        bitcoind_version = get_bitcoind_version(bitcoind_path)
    except RuntimeError as exc:
        pytest.exit(f"Cannot setup tests, bitcoind failing.\n{exc}")

    if bitcoind_version[0] >= 26:
        start_cmd += ' -allowignoredconf=1'
    local_command(start_cmd, bg=True)
    root_cmd = f'{bitcoincli_path} -regtest -rpcuser={rpcuser} -rpcpassword={rpcpassword}'
    wallet_name = 'jm-test-wallet'
    # Bitcoin Core v0.21+ does not create default wallet
    # From Bitcoin Core 0.21.0 there is support for descriptor wallets, which
    # are default from 23.x+ (including 22.99.0 development versions).
    # We don't support descriptor wallets yet.
    if bitcoind_version[0] >= 22:
        create_wallet = f'{root_cmd} -rpcwait -named createwallet wallet_name={wallet_name} descriptors=false'
    else:
        create_wallet = f'{root_cmd} -rpcwait createwallet {wallet_name}'
    local_command(create_wallet)
    local_command(f'{root_cmd} loadwallet {wallet_name}')
    for i in range(2):
        cpe = local_command(f'{root_cmd} -rpcwallet={wallet_name} getnewaddress')
        if cpe.returncode != 0:
            pytest.exit(f"Cannot setup tests, bitcoin-cli failing.\n{cpe.stdout.decode('utf-8')}")
        destn_addr = cpe.stdout[:-1].decode('utf-8')
        local_command(f'{root_cmd} -rpcwallet={wallet_name} generatetoaddress 301 {destn_addr}')
        sleep(1)
    yield
    # shut down bitcoind
    local_command(stop_cmd)
    # note, it is better to clean out ~/.bitcoin/regtest but too
    # dangerous to automate it here perhaps
