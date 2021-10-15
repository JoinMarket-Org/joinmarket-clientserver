The configuration format for IRC servers has changed.

Instead of the previous `[MESSAGING]` section there is now one section
for each server. In order to update your `joinmarket.cfg` you have to
move all options concerning one server into its own section with a
section name in the format of `[MESSAGING:servername]`.

example:

old config:

    [MESSAGING]
    host = irc.cyberguerrilla.org, agora.anarplex.net, another.irc.server.example.com
    channel = joinmarket-pit, joinmarket-pit, joinmarket-pit
    port = 6697, 14716, 12345
    usessl = true, true, false
    socks5 = false, false, false
    socks5_host = localhost, localhost, localhost
    socks5_port = 9050, 9050, 9050
    #for tor
    #host = 6dvj6v5imhny3anf.onion, cfyfz6afpgfeirst.onion
    #onion / i2p have their own ports on CGAN
    #port = 6698, 6667
    #usessl = true, false
    #socks5 = true, true

new config:

    [MESSAGING:server1]
    host = irc.cyberguerrilla.org
    channel = joinmarket-pit
    port = 6697
    usessl = true
    socks5 = false
    socks5_host = localhost
    socks5_port = 9050

    #for tor
    #host = 6dvj6v5imhny3anf.onion
    #onion / i2p have their own ports on CGAN
    #port = 6698
    #usessl = true
    #socks5 = true

    [MESSAGING:server2]
    host = agora.anarplex.net
    channel = joinmarket-pit
    port = 14716
    usessl = true
    socks5 = false
    socks5_host = localhost
    socks5_port = 9050

    #for tor
    #host = vxecvd6lc4giwtasjhgbrr3eop6pzq6i5rveracktioneunalgqlwfad.onion
    #port = 6667
    #usessl = false
    #socks5 = true

    [MESSAGING:exampleserver]
    host = another.irc.server.example.com
    channel = joinmarket-pit
    port = 12345
    usessl = false
    socks5 = false
    socks5_host = localhost
    socks5_port = 9050
