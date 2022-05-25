import jmbitcoin as btc


def test_address_descriptors():
    assert(btc.get_address_descriptor("1AGNa15ZQXAZUgFiqJ2i7Z2DPU2J6hW62i") ==
        "addr(1AGNa15ZQXAZUgFiqJ2i7Z2DPU2J6hW62i)#ns3f5w84")
    assert(btc.get_address_descriptor("3CMNFxN1oHBc4R1EpboAL5yzHGgE611Xou") ==
        "addr(3CMNFxN1oHBc4R1EpboAL5yzHGgE611Xou)#swk5gt6w")
    assert(btc.get_address_descriptor("bc1qt493axn3wl4gzjxvfg03vkacre0m6f2gzfhv5t") ==
        "addr(bc1qt493axn3wl4gzjxvfg03vkacre0m6f2gzfhv5t)#q8mdrmlw")


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

