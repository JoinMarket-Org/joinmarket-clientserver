import pytest
import copy
import jmbitcoin as btc

""" Awkward test module name `test_btc_snicker` is to avoid
    conflicts with snicker tests in jmclient.
"""

@pytest.mark.parametrize(
    "our_input_val, their_input_val, network_fee, script_type, net_transfer", [
        (24000000, 20000000, 2000, "p2wpkh", 100),
        (124000000, 20000000, 800, "p2wpkh", -100),
        (24000000, 20000000, 2000, "p2sh-p2wpkh", 100),
        (124000000, 20000000, 800, "p2sh-p2wpkh", -100),
    ])
def test_is_snicker_tx(our_input_val, their_input_val, network_fee,
                       script_type, net_transfer):
    our_input = (bytes([1])*32, 0)
    their_input = (bytes([2])*32, 1)
    assert our_input_val - their_input_val - network_fee > 0
    total_input_amount = our_input_val + their_input_val
    total_output_amount = total_input_amount - network_fee
    receiver_output_amount = their_input_val + net_transfer
    proposer_output_amount = total_output_amount - receiver_output_amount

    # all keys are just made up; only the script type will be checked
    privs = [bytes([i])*32 + bytes([1]) for i in range(1,4)]
    pubs = [btc.privkey_to_pubkey(x) for x in privs]

    if script_type == "p2wpkh":
        spks = [btc.pubkey_to_p2wpkh_script(x) for x in pubs]
    elif script_type == "p2sh-p2wpkh":
        spks = [btc.pubkey_to_p2sh_p2wpkh_script(x) for x in pubs]
    else:
        assert False
    tweaked_addr, our_addr, change_addr = [str(
        btc.CCoinAddress.from_scriptPubKey(x)) for x in spks]
    # now we must construct the three outputs with correct output amounts.
    outputs = [{"address": tweaked_addr, "value": receiver_output_amount}]
    outputs.append({"address": our_addr, "value": receiver_output_amount})
    outputs.append({"address": change_addr,
                    "value": total_output_amount - 2 * receiver_output_amount})
    assert all([x["value"] > 0 for x in outputs])

    # make_shuffled_tx mutates ordering (yuck), work with copies only:
    outputs1 = copy.deepcopy(outputs)
    # version and locktime as currently specified in the BIP
    # for 0/1 version SNICKER. (Note the locktime is partly because
    # of expected delays).
    tx = btc.make_shuffled_tx([our_input, their_input], outputs1,
                              version=2, locktime=0)
    assert btc.is_snicker_tx(tx)

    # construct variants which will be invalid.

    # mixed script types in outputs
    wrong_tweaked_spk = btc.pubkey_to_p2pkh_script(pubs[1])
    wrong_tweaked_addr = str(btc.CCoinAddress.from_scriptPubKey(
        wrong_tweaked_spk))
    outputs2 = copy.deepcopy(outputs)
    outputs2[0] = {"address": wrong_tweaked_addr,
                   "value": receiver_output_amount}
    tx2 = btc.make_shuffled_tx([our_input, their_input], outputs2,
                                  version=2, locktime=0)
    assert not btc.is_snicker_tx(tx2)

    # nonequal output amounts
    outputs3 = copy.deepcopy(outputs)
    outputs3[1] = {"address": our_addr, "value": receiver_output_amount - 1}
    tx3 = btc.make_shuffled_tx([our_input, their_input], outputs3,
                               version=2, locktime=0)
    assert not btc.is_snicker_tx(tx3)

    # too few outputs
    outputs4 = copy.deepcopy(outputs)
    outputs4 = outputs4[:2]
    tx4 = btc.make_shuffled_tx([our_input, their_input], outputs4,
                                   version=2, locktime=0)
    assert not btc.is_snicker_tx(tx4)

    # too many outputs
    outputs5 = copy.deepcopy(outputs)
    outputs5.append({"address": change_addr, "value": 200000})
    tx5 = btc.make_shuffled_tx([our_input, their_input], outputs5,
                                   version=2, locktime=0)
    assert not btc.is_snicker_tx(tx5)

    # wrong nVersion
    tx6 = btc.make_shuffled_tx([our_input, their_input], outputs,
                                       version=1, locktime=0)
    assert not btc.is_snicker_tx(tx6)

    # wrong nLockTime
    tx7 = btc.make_shuffled_tx([our_input, their_input], outputs,
                                           version=2, locktime=1)
    assert not btc.is_snicker_tx(tx7)
