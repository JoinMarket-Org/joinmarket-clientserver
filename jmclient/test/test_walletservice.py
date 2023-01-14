'''Tests of functionality at walletservice layer.'''

import os
import pytest
from jmbase import get_log
from jmclient import load_test_config, jm_single, \
     WalletService
from test_blockchaininterface import sync_test_wallet
from test_wallet import fund_wallet_addr, get_populated_wallet

pytestmark = pytest.mark.usefixtures("setup_regtest_bitcoind")

testdir = os.path.dirname(os.path.realpath(__file__))
log = get_log()

def set_freeze_reuse_config(x):
    jm_single().config.set('POLICY', 'max_sats_freeze_reuse', str(x))

def try_address_reuse(wallet_service, idx, funding_amt, config_threshold,
                      expected_final_balance):
    set_freeze_reuse_config(config_threshold)
    # check that below the threshold on the same address is not allowed:
    fund_wallet_addr(wallet_service.wallet, wallet_service.get_addr(0, 1, idx),
                     value_btc=funding_amt)
    wallet_service.transaction_monitor()
    balances = wallet_service.get_balance_by_mixdepth()
    assert balances[0] == expected_final_balance

def test_address_reuse_freezing(setup_walletservice):
    """ Creates a WalletService on a pre-populated wallet,
    and sets different values of the config var
    'max_sats_freeze_reuse' then adds utxos to different
    already used addresses to check that they are frozen or
    not as appropriate.
    Note that to avoid a twisted main loop the WalletService is
    not actually started, but the transaction_monitor is triggered
    manually (which executes the same code).
    A custom test version of the reuse warning callback is added
    and to check correct function, we check that this callback is
    called, and that the balance available in the mixdepth correctly
    reflects the usage pattern and freeze policy.
    """
    context = {'cb_called': 0}
    def reuse_callback(utxostr):
        context['cb_called'] += 1
    # we must fund after initial sync (for imports), hence
    # "populated" with no coins
    wallet = get_populated_wallet(num=0)
    wallet_service = WalletService(wallet)
    wallet_service.set_autofreeze_warning_cb(reuse_callback)
    sync_test_wallet(True, wallet_service)
    for i in range(3):
        fund_wallet_addr(wallet_service.wallet,
                         wallet_service.get_addr(0, 1, i))
    # manually force the wallet service to see the new utxos:
    wallet_service.transaction_monitor()

    # check that with default status any reuse is blocked:
    try_address_reuse(wallet_service, 0, 1, -1, 3 * 10**8)
    assert context['cb_called'] == 1, "Failed to trigger freeze callback"

    # check that above the threshold is allowed (1 sat less than funding)
    try_address_reuse(wallet_service, 1, 1, 99999999, 4 * 10**8)
    assert context['cb_called'] == 1, "Incorrectly triggered freeze callback"

    # check that below the threshold on the same address is not allowed:
    try_address_reuse(wallet_service, 1, 0.99999998, 99999999, 4 * 10**8)
    # note can be more than 1 extra call here, somewhat suboptimal:
    assert context['cb_called'] > 1, "Failed to trigger freeze callback"


@pytest.fixture(scope='module')
def setup_walletservice(request):
    load_test_config()
    old_reuse_freeze_val = jm_single().config.getint("POLICY",
                                    "max_sats_freeze_reuse")
    def reset_config():
        set_freeze_reuse_config(old_reuse_freeze_val)
    request.addfinalizer(reset_config)
