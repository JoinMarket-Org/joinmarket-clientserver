import jmbitcoin as btc
import pytest


def test_address_descriptors():
    assert(btc.get_address_descriptor("1AGNa15ZQXAZUgFiqJ2i7Z2DPU2J6hW62i") ==
        "addr(1AGNa15ZQXAZUgFiqJ2i7Z2DPU2J6hW62i)#ns3f5w84")
    assert(btc.get_address_from_descriptor("addr(1AGNa15ZQXAZUgFiqJ2i7Z2DPU2J6hW62i)#ns3f5w84") ==
        "1AGNa15ZQXAZUgFiqJ2i7Z2DPU2J6hW62i")
    assert(btc.get_address_descriptor("3CMNFxN1oHBc4R1EpboAL5yzHGgE611Xou") ==
        "addr(3CMNFxN1oHBc4R1EpboAL5yzHGgE611Xou)#swk5gt6w")
    assert(btc.get_address_from_descriptor("addr(3CMNFxN1oHBc4R1EpboAL5yzHGgE611Xou)#swk5gt6w") ==
        "3CMNFxN1oHBc4R1EpboAL5yzHGgE611Xou")
    assert(btc.get_address_descriptor("bc1qt493axn3wl4gzjxvfg03vkacre0m6f2gzfhv5t") ==
        "addr(bc1qt493axn3wl4gzjxvfg03vkacre0m6f2gzfhv5t)#q8mdrmlw")
    assert(btc.get_address_from_descriptor("addr(bc1qt493axn3wl4gzjxvfg03vkacre0m6f2gzfhv5t)#q8mdrmlw") ==
        "bc1qt493axn3wl4gzjxvfg03vkacre0m6f2gzfhv5t")
    assert(btc.get_address_descriptor("2MvAfRVvRAeBS18NT7mKVc1gFim169GkFC5") ==
        "addr(2MvAfRVvRAeBS18NT7mKVc1gFim169GkFC5)#h5yn9eq4")
    assert(btc.get_address_from_descriptor("addr(2MvAfRVvRAeBS18NT7mKVc1gFim169GkFC5)#h5yn9eq4") ==
        "2MvAfRVvRAeBS18NT7mKVc1gFim169GkFC5")
    with pytest.raises(ValueError):
        btc.get_address_from_descriptor("")
        btc.get_address_from_descriptor("pkh(xpub6CMAJ67vZWVXuzjzYXUoJgWrmuvFRiqiUG4dwoXNFmJtpTH3WgviANNxGyZYo27zxbMuqhDDym6fnBxmGaYoxr6LHgNDo1eEghkXHTX4Jnx/*)#flej8438")


def test_xpub_descriptors():
    assert(btc.get_xpub_descriptor(
        "xpub6CMAJ67vZWVXuzjzYXUoJgWrmuvFRiqiUG4dwoXNFmJtpTH3WgviANNxGyZYo27zxbMuqhDDym6fnBxmGaYoxr6LHgNDo1eEghkXHTX4Jnx", "p2pkh") ==
        "pkh(xpub6CMAJ67vZWVXuzjzYXUoJgWrmuvFRiqiUG4dwoXNFmJtpTH3WgviANNxGyZYo27zxbMuqhDDym6fnBxmGaYoxr6LHgNDo1eEghkXHTX4Jnx/*)#flej8438")
    assert(btc.get_xpub_descriptor(
        "xpub6CMAJ67vZWVXuzjzYXUoJgWrmuvFRiqiUG4dwoXNFmJtpTH3WgviANNxGyZYo27zxbMuqhDDym6fnBxmGaYoxr6LHgNDo1eEghkXHTX4Jnx", "p2sh-p2wpkh") ==
        "sh(wpkh(xpub6CMAJ67vZWVXuzjzYXUoJgWrmuvFRiqiUG4dwoXNFmJtpTH3WgviANNxGyZYo27zxbMuqhDDym6fnBxmGaYoxr6LHgNDo1eEghkXHTX4Jnx/*))#f2940w8j")
    assert(btc.get_xpub_descriptor(
        "xpub6CMAJ67vZWVXuzjzYXUoJgWrmuvFRiqiUG4dwoXNFmJtpTH3WgviANNxGyZYo27zxbMuqhDDym6fnBxmGaYoxr6LHgNDo1eEghkXHTX4Jnx", "p2wpkh") ==
        "wpkh(xpub6CMAJ67vZWVXuzjzYXUoJgWrmuvFRiqiUG4dwoXNFmJtpTH3WgviANNxGyZYo27zxbMuqhDDym6fnBxmGaYoxr6LHgNDo1eEghkXHTX4Jnx/*)#keekqdjc")

