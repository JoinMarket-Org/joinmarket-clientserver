# Joinmarket wallet API
Joinmarket wallet API

## Version: 1

### /wallet/create

#### POST
##### Summary

create a new wallet

##### Description

Give a filename (.jmdat must be included) and a password, create the wallet and get back the seedphrase for the newly persisted wallet file. The wallettype variable must be one of "sw" - segwit native, "sw-legacy" - segwit legacy or "sw-fb" - segwit native with fidelity bonds supported, the last of which is the default. Note that this operation cannot be performed when a wallet is already loaded (unlocked).

##### Responses

| Code | Description |
| ---- | ----------- |
| 201 | wallet created successfully |
| 400 | Bad request format. |
| 401 | Unable to authorise the credentials that were supplied. |
| 409 | Unable to complete request because object already exists. |

### /wallet/{walletname}/unlock

#### POST
##### Summary

decrypt an existing wallet

##### Description

Give the password for the specified (existing) wallet file, and it will be decrypted ready for use. Note that this operation cannot be performed when another wallet is already loaded (unlocked).

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ---- |
| walletname | path | name of wallet including .jmdat | Yes | string |

##### Responses

| Code | Description |
| ---- | ----------- |
| 200 | wallet unlocked successfully |
| 400 | Bad request format. |
| 401 | Unable to authorise the credentials that were supplied. |
| 404 | Item not found. |
| 409 | Unable to complete request because object already exists. |

### /wallet/{walletname}/lock

#### GET
##### Summary

block access to a currently decrypted wallet

##### Description

After this (authenticated) action, the wallet will not be readable or writeable.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ---- |
| walletname | path | name of wallet including .jmdat | Yes | string |

##### Responses

| Code | Description |
| ---- | ----------- |
| 200 | wallet unlocked successfully |
| 400 | Bad request format. |
| 401 | Unable to authorise the credentials that were supplied. |

##### Security

| Security Schema | Scopes |
| --- | --- |
| bearerAuth | |

### /wallet/{walletname}/display

#### GET
##### Summary

get detailed breakdown of wallet contents by account.

##### Description

get detailed breakdown of wallet contents by account.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ---- |
| walletname | path | name of wallet including .jmdat | Yes | string |

##### Responses

| Code | Description |
| ---- | ----------- |
| 200 | wallet display contents retrieved successfully. |
| 400 | Bad request format. |
| 401 | Unable to authorise the credentials that were supplied. |
| 404 | Item not found. |

##### Security

| Security Schema | Scopes |
| --- | --- |
| bearerAuth | |

### /session

#### GET
##### Summary

get current status of backend

##### Description

get whether a wallet is loaded and whether coinjoin/maker are happening.

##### Responses

| Code | Description |
| ---- | ----------- |
| 200 | successful heartbeat response |

### /wallet/all

#### GET
##### Summary

get current available wallets

##### Description

get all wallet filenames in standard location as a list

##### Responses

| Code | Description |
| ---- | ----------- |
| 200 | successful response to listwallets |

### /wallet/{walletname}/address/new/{mixdepth}

#### GET
##### Summary

get a fresh address in the given account for depositing funds.

##### Description

get a fresh address in the given account for depositing funds.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ---- |
| walletname | path | name of wallet including .jmdat | Yes | string |
| mixdepth | path | account or mixdepth to source the address from (0..4) | Yes | string |

##### Responses

| Code | Description |
| ---- | ----------- |
| 200 | successful retrieval of new address |
| 400 | Bad request format. |
| 401 | Unable to authorise the credentials that were supplied. |
| 404 | Item not found. |

##### Security

| Security Schema | Scopes |
| --- | --- |
| bearerAuth | |

### /wallet/{walletname}/address/timelock/new/{lockdate}

#### GET
##### Summary

get a fresh timelock address

##### Description

get a new timelocked address, for depositing funds, to create a fidelity bond, which will automatically be used when the maker is started. specify the date in YYYY-mm as the last path parameter. Note that mixdepth is not specified as timelock addresses are always in mixdepth(account) zero.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ---- |
| walletname | path | name of wallet including .jmdat | Yes | string |
| lockdate | path | month whose first day will be the end of the timelock, for this address. | Yes | string |

##### Responses

| Code | Description |
| ---- | ----------- |
| 200 | successful retrieval of new address |
| 400 | Bad request format. |
| 401 | Unable to authorise the credentials that were supplied. |
| 404 | Item not found. |

##### Security

| Security Schema | Scopes |
| --- | --- |
| bearerAuth | |

### /wallet/{walletname}/utxos

#### GET
##### Summary

list details of all utxos currently in the wallet.

##### Description

list details of all utxos currently in the wallet.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ---- |
| walletname | path | name of wallet including .jmdat | Yes | string |

##### Responses

| Code | Description |
| ---- | ----------- |
| 200 | successful retrieval of utxo list |
| 400 | Bad request format. |
| 401 | Unable to authorise the credentials that were supplied. |
| 404 | Item not found. |

##### Security

| Security Schema | Scopes |
| --- | --- |
| bearerAuth | |

### /wallet/{walletname}/taker/direct-send

#### POST
##### Summary

create and broadcast a transaction (without coinjoin)

##### Description

create and broadcast a transaction (without coinjoin)

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ---- |
| walletname | path | name of wallet including .jmdat | Yes | string |

##### Responses

| Code | Description |
| ---- | ----------- |
| 200 | transaction broadcast OK. |
| 400 | Bad request format. |
| 404 | Item not found. |
| 401 | Unable to authorise the credentials that were supplied. |
| 409 | Transaction failed to broadcast. |

##### Security

| Security Schema | Scopes |
| --- | --- |
| bearerAuth | |

### /wallet/{walletname}/maker/start

#### POST
##### Summary

Start the yield generator service.

##### Description

Start the yield generator service with the configuration settings specified in the POST request. Note that if fidelity bonds are enabled in the wallet, and a timelock address has been generated, and then funded, the fidelity bond will automatically be advertised without any specific configuration in this request. Note that if the wallet does not have confirmed coins, or another taker or maker coinjoin service is already running, the maker will not start.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ---- |
| walletname | path | name of wallet including .jmdat | Yes | string |

##### Responses

| Code | Description |
| ---- | ----------- |
| 202 | The request has been submitted successfully for processing, but the processing has not been completed. |
| 400 | Bad request format. |
| 401 | Unable to authorise the credentials that were supplied. |
| 404 | Item not found. |
| 409 | Maker could not start without confirmed balance. |
| 503 | The server is not ready to process the request. |

##### Security

| Security Schema | Scopes |
| --- | --- |
| bearerAuth | |

### /wallet/{walletname}/maker/stop

#### GET
##### Summary

stop the yield generator service

##### Description

stop the yield generator service

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ---- |
| walletname | path | name of wallet including .jmdat | Yes | string |

##### Responses

| Code | Description |
| ---- | ----------- |
| 202 | The request has been submitted successfully for processing, but the processing has not been completed. |
| 400 | Bad request format. |
| 401 | Unable to authorise the credentials that were supplied. |
| 404 | Item not found. |

##### Security

| Security Schema | Scopes |
| --- | --- |
| bearerAuth | |

### /wallet/{walletname}/taker/coinjoin

#### POST
##### Summary

initiate a coinjoin as taker

##### Description

initiate a coinjoin as taker

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ---- |
| walletname | path | name of wallet including .jmdat | Yes | string |

##### Responses

| Code | Description |
| ---- | ----------- |
| 202 | The request has been submitted successfully for processing, but the processing has not been completed. |
| 400 | Bad request format. |
| 401 | Unable to authorise the credentials that were supplied. |
| 404 | Item not found. |
| 409 | Unable to complete request because config settings are missing. |
| 503 | The server is not ready to process the request. |

##### Security

| Security Schema | Scopes |
| --- | --- |
| bearerAuth | |

### /wallet/{walletname}/taker/stop

#### GET
##### Summary

stop a running coinjoin attempt

##### Description

stop a running coinjoin attempt

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ---- |
| walletname | path | name of wallet including .jmdat | Yes | string |

##### Responses

| Code | Description |
| ---- | ----------- |
| 202 | The request has been submitted successfully for processing, but the processing has not been completed. |
| 400 | Bad request format. |
| 401 | Unable to authorise the credentials that were supplied. |
| 404 | Item not found. |

##### Security

| Security Schema | Scopes |
| --- | --- |
| bearerAuth | |

### /wallet/{walletname}/configset

#### POST
##### Summary

change a config variable

##### Description

change a config variable (for the duration of this backend daemon process instance)

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ---- |
| walletname | path | name of wallet including .jmdat | Yes | string |

##### Responses

| Code | Description |
| ---- | ----------- |
| 200 | successful update of config value |
| 400 | Bad request format. |
| 401 | Unable to authorise the credentials that were supplied. |
| 409 | Unable to complete request because config settings are missing. |

##### Security

| Security Schema | Scopes |
| --- | --- |
| bearerAuth | |

### /wallet/{walletname}/configget

#### POST
##### Summary

get the value of a specific config setting

##### Description

Get the value of a specific config setting. Note values are always returned as string.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ---- |
| walletname | path | name of wallet including .jmdat | Yes | string |

##### Responses

| Code | Description |
| ---- | ----------- |
| 200 | successful retrieval of config value |
| 400 | Bad request format. |
| 401 | Unable to authorise the credentials that were supplied. |
| 409 | Unable to complete request because config settings are missing. |

##### Security

| Security Schema | Scopes |
| --- | --- |
| bearerAuth | |

### /wallet/{walletname}/getseed

#### GET
##### Summary

get the mnemonic recovery phrase with the optional passphrase

##### Description

Get the mnemonic recovery phrase with the optional passphrase. Not the response is a sentence with few line breaks.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ---- |
| walletname | path | name of the wallet including .jmdat | Yes | string |

##### Responses

| Code | Description |
| ---- | ----------- |
| 200 | seedphrase retrieved successfully |
| 400 | Bad request format. |
| 401 | Unable to authorise the credentials that were supplied. |

##### Security

| Security Schema | Scopes |
| --- | --- |
| bearerAuth | |

### Models

#### ConfigSetRequest

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| section | string |  | Yes |
| field | string |  | Yes |
| value | string |  | Yes |

#### ConfigGetRequest

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| section | string |  | Yes |
| field | string |  | Yes |

#### ConfigGetResponse

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| configvalue | string |  | Yes |

#### ConfigSetResponse

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| ConfigSetResponse | object |  |  |

#### DoCoinjoinRequest

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| mixdepth | integer | _Example:_ `0` | Yes |
| amount_sats | integer |_Example:_ `100000000` | Yes |
| counterparties | integer | _Example:_ `9` | Yes |
| destination | string | _Example:_ `"bcrt1qujp2x2fv437493sm25gfjycns7d39exjnpptzw"` | Yes |

#### StartMakerRequest

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| txfee | string | _Example:_ `"0"` | Yes |
| cjfee_a | string |_Example:_ `"5000"` | Yes |
| cjfee_r | string |_Example:_ `"0.00004"` | Yes |
| ordertype | string | _Example:_ `"reloffer"` | Yes |
| minsize | string | _Example:_ `"8000000"` | Yes |

#### GetAddressResponse

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| GetAddressResponse | string |  |  |

**Example**
<pre>bcrt1qujp2x2fv437493sm25gfjycns7d39exjnpptzw</pre>

#### ListWalletsResponse

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| wallets | [ string ] |  | No |

#### SessionResponse

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| session | boolean |  | Yes |
| maker_running | boolean |  | Yes |
| coinjoin_in_process | boolean |  | Yes |
| wallet_name | string |_Example:_ `"wallet.jmdat"` | Yes |

#### ListUtxosResponse

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| utxos | [ object ] |  | No |

#### WalletDisplayResponse

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| walletname | string |  | Yes |
| walletinfo | object |  | Yes |

#### CreateWalletResponse

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| walletname | string | _Example:_ `"wallet.jmdat"` | Yes |
| token | byte |  | Yes |
| seedphrase | string |  | Yes |

#### UnlockWalletResponse

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| walletname | string | _Example:_ `"wallet.jmdat"` | Yes |
| token | byte |  | Yes |

#### DirectSendResponse

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| txinfo | object |  | Yes |

#### GetSeedResponse

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| seedphrase | string |  | Yes |

#### LockWalletResponse

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| walletname | string | _Example:_ `"wallet.jmdat"` | Yes |
| already_locked | boolean |_Example:_ `false` | Yes |

#### CreateWalletRequest

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| walletname | string | _Example:_ `"wallet.jmdat"` | Yes |
| password | password | _Example:_ `"hunter2"` | Yes |
| wallettype | string | _Example:_ `"sw-fb"` | Yes |

#### UnlockWalletRequest

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| password | password | _Example:_ `"hunter2"` | Yes |

#### DirectSendRequest

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| mixdepth | integer | _Example:_ `0` | Yes |
| amount_sats | integer |_Example:_ `100000000` | Yes |
| destination | string | _Example:_ `"bcrt1qu7k4dppungsqp95nwc7ansqs9m0z95h72j9mze"` | Yes |

#### ErrorMessage

| Name | Type | Description | Required |
| ---- | ---- | ----------- | -------- |
| message | string |  | No |
