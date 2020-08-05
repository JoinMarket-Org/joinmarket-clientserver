## JSON-RPC API for Joinmarket using jmwalletd.py

### Introduction - how to start the server

After installing Joinmarket as per the [INSTALL GUIDE](INSTALL.md), navigate to the `scripts/` directory as usual and start the server with:

```
(jmvenv) $python jmwalletd.py
```

which with defaults will start serving the RPC over HTTP on port 28183.

This HTTP server does *NOT* currently support multiple sessions; it is intended as a manager/daemon for all the Joinmarket services for a single user.

#### Rules about making requests

Currently authentication is done by providing a cookie on first request, which must then be reused to keep the same session. The cookie is sent in an HTTP header with name `b'JMCookie'`. This is fine for an early testing stage, but will be improved/reworked, and that will be documented here.

GET requests are used in case no content or parameters need to be provided with the request.

POST requests are used in case content or parameters are to be provided with the request, and they are provided as utf-8 encoded serialized JSON, in the *body* of the POST request.

Note that for some methods, it's particularly important to deal with the HTTP response asynchronously, since it can take some time for wallet synchronization, service startup etc. to occur.

### Methods

#### `createwallet`

Make a new wallet. The variable "wallettype" should be "sw" for native segwit wallets (now the Joinmarket default), otherwise a segwit legacy wallet (BIP49) will be created.

* HTTP Request type: POST
* Route: `/wallet/create`
* POST body contents: {"walletname": walletname, "password": password, "wallettype": wallettype}
* Returns: on success, {"walletname": walletname, "already_loaded": False}

(TODO some confusion over two different walletnames here, I need to check, but the wallet name sent by the caller will be used for the file name, I believe).

#### `unlockwallet`

Open an existing wallet using a password.

* HTTP Request type: POST
* Route: `/wallet/<string:walletname>/unlock`
* POST body contents: {"password": password}
* Returns: on success, {"walletname": walletname, "already_loaded": True}

(see previous on walletname, same applies here).

#### `lockwallet`

Stops the wallet service for the current wallet; meaning it cannot then be accessed without re-authentication.

* HTTP Request type: GET
* Route: `/wallet/<string:walletname>/lock`
* Returns: on success, {"walletname": walletname}

(see previous on walletname, same applies here).

#### `displaywallet`

Get JSON representation of wallet contents for wallet named `walletname`:

* HTTP Request type: GET
* Route: `/wallet/<string:walletname>/display`
* Returns: a JSON object which is the entire wallet contents, mixdepth by mixdepth.
    - Example output from a signet wallet is given at the bottom of the document.

#### `maker/start`

Starts the yield generator/maker service for the given wallet, using the IRC and tor network connections
in the backend (inside the process started with jmwalletd).
See Joinmarket yield generator config defaults in `jmclient.configure` module for info on the data that must
be specified in the POST body contents.

* HTTP Request type: POST
* Route: `/wallet/<string:walletname>/maker/start`
* POST body contents: {"txfee", "cjfee_a", "cjfee_r", "ordertype", "minsize"]
* Returns: on success, {"walletname": walletname}

(see previous on walletname, same applies here).

#### `maker/stop`

Stops the yieldgenerator/maker service if currently running for the given wallet.

* HTTP Request type: GET
* Route: `/wallet/<string:walletname>/maker/start`
* Returns: on success, {"walletname": walletname}

(see previous on walletname, same applies here).

#### `snicker/start`

Starts the SNICKER service (see [here](SNICKER.md)) for the given wallet. Note that this requires
no configuration for now, though that is likely to change. Also note this is not yet supported for
mainnet.

* HTTP Request type: GET
* Route: `/wallet/<string:walletname>/snicker/start`
* Returns: on success, {"walletname": walletname}

(see previous on walletname, same applies here).

#### `snicker/stop`

Stops the snicker service if currently running for the given wallet.

* HTTP Request type: GET
* Route: `/wallet/<string:walletname>/snicker/start`
* Returns: on success, {"walletname": walletname}

(see previous on walletname, same applies here).

##### Example wallet display JSON output from signet wallet

```
{'wallet_name': 'JM wallet', 'total_balance': '0.15842426', 'accounts': [{'account': '0', 'account_balance': '0.00861458', 'branches': [{'branch': "external addresses\tm/84'/1'/0'/0\ttpubDFGxEsV7NvVc4h2XL4QEppZt3CrDiCFksP97H6YbFPmCTKM6KMP2xUxW57gAu7bzDfB3YTqnMeKQaQRS5GJM3xMcrhbi5AGsQUd7p4PLMDV", 'balance': '0.00000000', 'entries': [{'hd_path': "m/84'/1'/0'/0/4", 'address': 'tb1qzugshsm85x6luegyjc6mk5zces2zqr0j8m4zkd', 'amount': '0.00000000', 'labels': 'new'}, {'hd_path': "m/84'/1'/0'/0/5", 'address': 'tb1qcwmdkg229ghmd8r3xgq4a9zxp459crws66n4ve', 'amount': '0.00000000', 'labels': 'new'}, {'hd_path': "m/84'/1'/0'/0/6", 'address': 'tb1q7lv6dwex3mhwp32vhku0fvpar9faar2lu595su', 'amount': '0.00000000', 'labels': 'new'}, {'hd_path': "m/84'/1'/0'/0/7", 'address': 'tb1qm42ltytvp22kj9efp995yu0r0r7x570d8j8crc', 'amount': '0.00000000', 'labels': 'new'}, {'hd_path': "m/84'/1'/0'/0/8", 'address': 'tb1qwvux8g0khuvvkla3zaqdslj6xpgwtq7jlvwmgu', 'amount': '0.00000000', 'labels': 'new'}, {'hd_path': "m/84'/1'/0'/0/9", 'address': 'tb1q3xr7l9nylsdlyqf9rkw0rg3f0yx6slguhtwpzp', 'amount': '0.00000000', 'labels': 'new'}]}, {'branch': "internal addresses\tm/84'/1'/0'/1\t", 'balance': '0.00861458', 'entries': [{'hd_path': "m/84'/1'/0'/1/7", 'address': 'tb1qjrzxkulgc5dnlyz0rjqj68zxgqjesqn839ue2w', 'amount': '0.00396839', 'labels': 'cj-out'}, {'hd_path': "m/84'/1'/0'/1/12", 'address': 'tb1qeqkk4te2t6gqt7jfgu8a9k4je2wwfw3d2m7gku', 'amount': '0.00464619', 'labels': 'non-cj-change'}]}]}, {'account': '1', 'account_balance': '0.09380968', 'branches': [{'branch': "external addresses\tm/84'/1'/1'/0\ttpubDE1TKa8tm3WWh4f9fV325BgYWX9i7WFMaQRd1C3tSFYU9RJEyE8w2Cw2KnhgXSKyjS4keeWAkc3iLEqp3pxUEG9T49RCtQiMpjuZM71FLpL", 'balance': '0.00000000', 'entries': [{'hd_path': "m/84'/1'/1'/0/0", 'address': 'tb1qd6qqg3uzk9sw88yhvpqpwt3tx5ls4hau3mwh3g', 'amount': '0.00000000', 'labels': 'new'}, {'hd_path': "m/84'/1'/1'/0/1", 'address': 'tb1qhkrmqn9e4ldzlwna8w5w9l5vaw978zlrl54hmh', 'amount': '0.00000000', 'labels': 'new'}, {'hd_path': "m/84'/1'/1'/0/2", 'address': 'tb1qp83afad8dl98w366vnvct0zc49qu33c2nfx386', 'amount': '0.00000000', 'labels': 'new'}, {'hd_path': "m/84'/1'/1'/0/3", 'address': 'tb1qjv0elh4kn5yaywajedgcrf93ujzz3m3q7ld7k3', 'amount': '0.00000000', 'labels': 'new'}, {'hd_path': "m/84'/1'/1'/0/4", 'address': 'tb1qk25u4ch7w0xylzh0krn4hefphe6xpyh0vc33sl', 'amount': '0.00000000', 'labels': 'new'}, {'hd_path': "m/84'/1'/1'/0/5", 'address': 'tb1qs3ep9nlypwn43swv75zwv6lgl3wgsmha20g87p', 'amount': '0.00000000', 'labels': 'new'}]}, {'branch': "internal addresses\tm/84'/1'/1'/1\t", 'balance': '0.09380968', 'entries': [{'hd_path': "m/84'/1'/1'/1/44", 'address': 'tb1qgmgpk22ueq9xk8f722aqjnuwd6s3jv58nwwan2', 'amount': '0.00009631', 'labels': 'non-cj-change'}, {'hd_path': "m/84'/1'/1'/1/49", 'address': 'tb1qjq86y8nzvafv5dsde93zf0emv7yrsphvupv69e', 'amount': '0.00013383', 'labels': 'non-cj-change'}, {'hd_path': "m/84'/1'/1'/1/54", 'address': 'tb1q7lvxk407xs38t24hfzy7vprp9t7tfsemv4rfym', 'amount': '0.00371951', 'labels': 'non-cj-change'}, {'hd_path': "m/84'/1'/1'/1/56", 'address': 'tb1qn2azshrkcg0d7py5apgfr0jh29nt9w2fmx9fyy', 'amount': '0.08986003', 'labels': 'non-cj-change'}]}, {'branch': 'Imported keys\tm/0\t', 'balance': '0.00000000', 'entries': [{'hd_path': 'imported/1/0', 'address': 'tb1q8znprh8c85za3mpwzn3qf9m0vwqzjkfu4qdncy', 'amount': '0.00000000', 'labels': 'empty'}, {'hd_path': 'imported/1/1', 'address': 'tb1qu4ajg3enea90xxtjuwcurj3d6lkqrud8p7w0yu', 'amount': '0.00000000', 'labels': 'empty'}, {'hd_path': 'imported/1/2', 'address': 'tb1qg7saqx69yalcqshfr8mjndy0gpx2umxrwqs823', 'amount': '0.00000000', 'labels': 'empty'}]}]}, {'account': '2', 'account_balance': '0.05600000', 'branches': [{'branch': "external addresses\tm/84'/1'/2'/0\ttpubDF8K7wXCrRXX1CQLVZGwMvEg9YEWF2VRpM1tjCwpMZDRRqKjpJ5YaeaDaLkqN1D7YM4pkX32FcCnosbhLQz2BgRiPNNdybWuvSBKp72mJsJ", 'balance': '0.00000000', 'entries': [{'hd_path': "m/84'/1'/2'/0/0", 'address': 'tb1qw95x9m84t6hqcun560vqfk3yc6ptl4g9arsty0', 'amount': '0.00000000', 'labels': 'new'}, {'hd_path': "m/84'/1'/2'/0/1", 'address': 'tb1qek4humez7rcwl53ly6uzr4mfwd0s2lu92e356q', 'amount': '0.00000000', 'labels': 'new'}, {'hd_path': "m/84'/1'/2'/0/2", 'address': 'tb1qxne4hyyeq2vrh0dfzs56th29qsymp9eq5pljdc', 'amount': '0.00000000', 'labels': 'new'}, {'hd_path': "m/84'/1'/2'/0/3", 'address': 'tb1qz3jk544j5vtwztznxfdwfgt8zcw77mjcut8vdz', 'amount': '0.00000000', 'labels': 'new'}, {'hd_path': "m/84'/1'/2'/0/4", 'address': 'tb1qg902humlsuc5s6aua6ew3d893hlgcxr05ntpyd', 'amount': '0.00000000', 'labels': 'new'}, {'hd_path': "m/84'/1'/2'/0/5", 'address': 'tb1qukz3l34ydy9snq8rkjaknk0ns04kfnlh34neqd', 'amount': '0.00000000', 'labels': 'new'}]}, {'branch': "internal addresses\tm/84'/1'/2'/1\t", 'balance': '0.05600000', 'entries': [{'hd_path': "m/84'/1'/2'/1/1", 'address': 'tb1qrtz5cwpneheg2v2v32wzc3h9yv0rzplxjtx9vc', 'amount': '0.00800000', 'labels': 'non-cj-change'}, {'hd_path': "m/84'/1'/2'/1/2", 'address': 'tb1qp4276g23y2w8g3367de25ustxkygjydmwk4fw2', 'amount': '0.00800000', 'labels': 'non-cj-change'}, {'hd_path': "m/84'/1'/2'/1/3", 'address': 'tb1qtqgvw445807tzcm8yhq6xgu3vmdfh66czx8jea', 'amount': '0.00800000', 'labels': 'non-cj-change'}, {'hd_path': "m/84'/1'/2'/1/4", 'address': 'tb1qxj7ulxdthe0dwxr5457p5d0w5u3jg7rwmc05pm', 'amount': '0.02400000', 'labels': 'non-cj-change'}, {'hd_path': "m/84'/1'/2'/1/5", 'address': 'tb1qv3kfe9ew42z0ldncgzmqcjznatsxz0vudvcjrv', 'amount': '0.00800000', 'labels': 'non-cj-change'}]}]}, {'account': '3', 'account_balance': '0.00000000', 'branches': [{'branch': "external addresses\tm/84'/1'/3'/0\ttpubDE9VN56aLW9BurCxHHGAWidSnVuU86ZsKPYQgxpTgkZxbogJYfj1vWJbtYip7WV5REcgmtjETb5eShXV8VUBzvCAMzuRm5Kv4ZGnnCiX6Jg", 'balance': '0.00000000', 'entries': [{'hd_path': "m/84'/1'/3'/0/0", 'address': 'tb1qp2w6ezmqn8nk9kc4gkpetgjj2mzqgp5x3hk86m', 'amount': '0.00000000', 'labels': 'new'}, {'hd_path': "m/84'/1'/3'/0/1", 'address': 'tb1qd0tt93aulqs508mtap5p8gls5z57fqa4ggnfx7', 'amount': '0.00000000', 'labels': 'new'}, {'hd_path': "m/84'/1'/3'/0/2", 'address': 'tb1qsp4hv46vgz4yjwt4p2wekh2gfmek7vgznrnd96', 'amount': '0.00000000', 'labels': 'new'}, {'hd_path': "m/84'/1'/3'/0/3", 'address': 'tb1qvs322uyrwh7a74dsxel0xcrgucm27c6dzdmj9j', 'amount': '0.00000000', 'labels': 'new'}, {'hd_path': "m/84'/1'/3'/0/4", 'address': 'tb1qnq9uk9azs9s7m5474ws7z7wxnwv3s3lxrtjter', 'amount': '0.00000000', 'labels': 'new'}, {'hd_path': "m/84'/1'/3'/0/5", 'address': 'tb1q5tlq36q6ps0m9zu6h08gd3azsgkgvm73sjcmxw', 'amount': '0.00000000', 'labels': 'new'}]}, {'branch': "internal addresses\tm/84'/1'/3'/1\t", 'balance': '0.00000000', 'entries': []}]}, {'account': '4', 'account_balance': '0.00000000', 'branches': [{'branch': "external addresses\tm/84'/1'/4'/0\ttpubDE6QfTimeNgCFSYuxPPaLc1Cp3VokAuJAusYoiGwWtVHVtQDsepf5dRAFNLWMwpBCgKDYkXdWGs2JspxXPokrtooPh7db5fniqYbdKGqD4F", 'balance': '0.00000000', 'entries': [{'hd_path': "m/84'/1'/4'/0/3", 'address': 'tb1qr2llfup6cnh27n77nm7egcyf9r7c0ykucrcu8k', 'amount': '0.00000000', 'labels': 'new'}, {'hd_path': "m/84'/1'/4'/0/4", 'address': 'tb1qahqjnd2y8j770l2m4kpf4fyfve9425c0zdumms', 'amount': '0.00000000', 'labels': 'new'}, {'hd_path': "m/84'/1'/4'/0/5", 'address': 'tb1q0jm0cxwcm2g60489fvtmeeaf7mzg658t8f8fk4', 'amount': '0.00000000', 'labels': 'new'}, {'hd_path': "m/84'/1'/4'/0/6", 'address': 'tb1qtpm5putpkzmrmecden0yytuuk4n9emhvxwqu8m', 'amount': '0.00000000', 'labels': 'new'}, {'hd_path': "m/84'/1'/4'/0/7", 'address': 'tb1qn60fc04pmprn9wpzkt0dnt80awu0rpy99w376g', 'amount': '0.00000000', 'labels': 'new'}, {'hd_path': "m/84'/1'/4'/0/8", 'address': 'tb1qakvrpp2hd3a3303zx7w2shmvfc7tqk28pwa9sj', 'amount': '0.00000000', 'labels': 'new'}]}, {'branch': "internal addresses\tm/84'/1'/4'/1\t", 'balance': '0.00000000', 'entries': []}]}]}
```