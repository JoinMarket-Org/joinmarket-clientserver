from jmclient import old_mnemonic

import pytest


@pytest.mark.parametrize(
    "seedphrase, key, valid",
    [
        (["spiral", "squeeze", "strain", "sunset", "suspend", "sympathy",
          "thigh", "throne", "total", "unseen", "weapon", "weary"],
         '0028644c0028644f0028645200286455',
         True),
        (["pair", "bury", "lung", "swim", "orange", "doctor", "numb", "interest",
          "shock", "bloom", "fragile", "screen"],
         'fa92999d01431f961a26c876f55d3f6c',
         True),
        (["check", "squeeze", "strain", "sunset", "suspend", "sympathy",
          "thigh", "throne", "total", "unseen", "weapon", "weary"],
         '0028644c0028644f0028645200286455',
         False),
        (["qwerty", "check", "strain", "sunset", "suspend", "sympathy",
          "thigh", "throne", "total", "unseen", "weapon", "weary"],
         '',
         False),
        (["", "check", "strain", "sunset", "suspend", "sympathy",
          "thigh", "throne", "total", "unseen", "weapon", "weary"],
         '',
         False),
        (["strain", "sunset"],
         '',
         False),
    ])
def test_old_mnemonic(seedphrase, key, valid):
    if valid:
        assert old_mnemonic.mn_decode(seedphrase) == key
        assert old_mnemonic.mn_encode(key) == seedphrase
    else:
        if len(key) > 0:
            # test cases where the seedphrase is valid 
            # but must not match the provided master private key
            assert old_mnemonic.mn_decode(seedphrase) != key
        else:
            # test cases where the seedphrase is intrinsically invalid
            # Already known error condition: an incorrectly short
            # word list will NOT throw an error; this is handled by calling code
            if len(seedphrase) < 12:
                print "For known failure case of seedphrase less than 12: "
                print old_mnemonic.mn_decode(seedphrase)
            else:
                with pytest.raises(Exception) as e_info:
                    dummy = old_mnemonic.mn_decode(seedphrase)
                    print "Got this return value from mn_decode: " + str(dummy)
