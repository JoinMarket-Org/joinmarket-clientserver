### How to use Tor with Joinmarket

(You've installed using the `install.sh` or similar as per instructions in the README before
reading this).

This document gives short notes on any necessary configuration steps for using Joinmarket as a Maker or a Taker, in coinjoins.
The requirements for Takers are lesser.

### Contents

1. [Checking Tor is installed](#torinstall)

2. [Using Tor as a Taker](#tortaker)

3. [Using Tor as a Maker](#tormaker)

   a. [Configuring Tor to setup an onion service](#torconfig)

<a name="torinstall">

### Checking Tor is installed

(Insert sanity check advice for system `tor`.)

If you don't currently have a Tor daemon running on your machine you can use the flag `--with-local-tor` appended to your invocation of `./install.sh` as per the installation instructions in the README.

<a name="tortaker">

### Using Tor as a Taker

Insert basic instructions on checking Tor is functional and SOCKS port.

<a name="tormaker">

### Using Tor as a Maker

To use the new onion messaging system (see [here](onion-message-channels.md)) as a maker it's necessary for your bot to be reachable directly p2p by takers, so you need to run an onion service. This often requires a little extra configuration of your Tor setup, which we now explain:

<a name="torconfig" />

#### Configuring Tor to setup an onion service

(These steps were prepared using Ubuntu; you may have to adjust for your distro).

First, ensure you have Tor installed:

```
sudo apt install tor
```

Don't start the tor daemon yet though, since we need to do some setup. Edit Tor's config file with sudo:

```
sudo vim /etc/tor/torrc
```

and uncomment these three lines to enable onion service startup:

```
ControlPort 9051
CookieAuthentication 1
CookieAuthFileGroupReadable 1
```

However if you proceed at this point to try to start your yieldgenerator with `python yg-privacyenhanced.py wallet.jmdat` or similar, you will almost certainly get an error like this:

```
Permission denied: '/var/run/tor/control.authcookie'
```

... because reading this file requires being a member of the group `debian-tor`. So add your user to this group:

```
sudo usermod -a -G debian-tor yourusername
```

... and then you must *restart the computer/server* (or maybe just logout, login) for that change to take effect (check it with `groups yourusername`).

Finally, after system restart, ensure Tor is started (it may be automatically, but anyway):

```
sudo service tor start
```

Once this is done, you should be able to start the yieldgenerator successfully.

#### Tor-managed hidden services

As an alternative to using the Tor control port, you can configure Tor to manage the hidden service directly via its configuration file (`torrc`). This approach is useful when:

- You want Tor to fully manage the hidden service lifecycle
- You don't want to grant control port access to JoinMarket
- You're running Tor as a system service and prefer centralized configuration

To use this mode:

1. Configure the hidden service in Tor's `torrc` file (typically `/etc/tor/torrc`):

   ```ini
   HiddenServiceDir /var/lib/tor/joinmarket_hidden_service
   HiddenServicePort 5222 127.0.0.1:8080
   ```

2. Set appropriate permissions
3. Restart To
4. Configure JoinMarket to use the Tor-managed service by setting `hidden_service_dir` in your `joinmarket.cfg`:

   ```ini
   hidden_service_dir = tor-managed:/var/lib/tor/joinmarket_hidden_service
   ```

   Note the `tor-managed:` prefix, which tells JoinMarket to read the hostname from the `hostname` file in that directory rather than managing the service via the control port.

##### Important notes

- The directory path in `hidden_service_dir` must match exactly what's configured in `torrc`
- JoinMarket will read the hostname from the `hostname` file; make sure Tor has created it
- No control port configuration is needed for this mode (though you may still need it for other features)
- The hidden service directory must be readable by the user running JoinMarket (or the `hostname` file at minimum)
