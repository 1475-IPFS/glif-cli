<img src="./logo.png" alt="GLIF Logo" align="right" width="60px" />

# GLIF CLI

![Github Actions][gha-badge] ![Discord Channel][discord-badge]

[gha-badge]: https://img.shields.io/github/actions/workflow/status/glifio/cli/test.yml?branch=main
[discord-badge]: https://dcbadge.vercel.app/api/server/5qsJjsP3Re?style=flat-square&theme=clean-inverted&compact=true&theme=blurple

**The GLIF Command Line Interface is the starting point for interacting with the GLIF Pools Protocol.**

- [GLIF CLI](#glif-cli)
  - [Installation](#installation)
  - [Named wallet accounts and addresses](#named-wallet-accounts-and-addresses)
  - [Wallets](#wallets)
    - [List existing wallet accounts and balances](#list-existing-wallet-accounts-and-balances)
    - [Creating wallet accounts for use with an Agent](#creating-wallet-accounts-for-use-with-an-agent)
    - [Generic wallet accounts](#generic-wallet-accounts)
    - [Passphrases](#passphrases)
    - [Migrate from a legacy keystore.toml wallet](#migrate-from-a-legacy-keystoretoml-wallet)
  - [Agents - Get started borrowing](#agents---get-started-borrowing)
    - [Create an Agent](#create-an-agent)
    - [Add a Miner to an Agent](#add-a-miner-to-an-agent)
    - [Borrow](#borrow)
    - [Moving FIL from Miner to Agent and back](#moving-fil-from-miner-to-agent-and-back)
    - [Withdraw Rewards / Cash Advance](#withdraw-rewards--cash-advance)
    - [Remove a Miner from an Agent](#remove-a-miner-from-an-agent)
  - [Payments](#payments)
    - [Payment types](#payment-types)
    - [Autopilot](#autopilot)
    - [Leaving the pool](#leaving-the-pool)
  - [Agent health](#agent-health)
  - [Advanced Mode](#advanced-mode)
    - [Reset your Agent's owner key](#reset-your-agents-owner-key)
    - [Reset your Agent's operator key](#reset-your-agents-operator-key)
    - [Reset your Agent's requester key](#reset-your-agents-requester-key)

<hr />

## Installation

First, clone the repo from GitHub:<br />
`git clone git@github.com:glifio/cli.git`<br />
`cd cli`<br />

**Mainnet installation**<br />
`make glif`<br />
`sudo make install`<br />
`make config`<br />

**Testnet installation**<br />
`make calibnet`<br />
`sudo make install`<br />
`make calibnet-config`<br />

## Named wallet accounts and addresses

The GLIF CLI maps human readable names to account addresses. Whenever you pass an `address` argument or flag to a command, you can use the human readable version of the name. For example, if you have an account named `testing-account`, you can specify sending a transaction `from` `testing-account` by:

`glif <command> <command-args> --from testing-account`<br />

To create a read-only label for an arbitrary address:<br />
`glif wallet label-account <name> <address>`<br />

Note that if you add a built-in actor's address (`f1/f2/f3`), it will be converted to an `f0` ID Address and encoded into a `0x` EVM address format. `0x` style addresses are used when interacting with smart contracts on the FEVM. Read more about it [here](https://docs.filecoin.io/smart-contracts/filecoin-evm-runtime/address-types/#converting-to-a-0x-style-address).

To list all your accounts, including read-only labeled ones:<br />
`glif wallet list --include-read-only`

## Wallets

The GLIF CLI embeds a wallet inside of it for writing transactions to Filecoin. The wallet is built off of [go-ethereum's encrypted keystore](https://geth.ethereum.org/docs/developers/dapp-developer/native-accounts). A single "wallet" can hold many separate "accounts", and each "account" has a human readable name.

The encrypted account information is stored at `~/.glif/keystore` and the human readable name to address mappings are stored in `~/.glif/accounts`

Note that all wallet accounts are EVM actor types, meaning they have a 0x/f4 address on Filecoin. The GLIF CLI wallet does not yet support f1/f2/f3 style addresses.

### List existing wallet accounts and balances

`glif wallet list`<br />

To include

`glif wallet balance`<br />

### Creating wallet accounts for use with an Agent

`glif wallet create-agent-accounts`

This command will create 3 new wallet accounts: (1) `owner`, (2) `operator`, and (3) `requester`, which correspond to an Agent smart contract. You can read more about those keys in our [docs](https://docs.glif.io/agents/owner-and-address-keys).

**It is strongly recommended to securely backup your `owner` encrypted key - losing this key means losing access to your Agent**.

### Generic wallet accounts

You can also create generic named wallets for use in other commands:<br />
`glif wallet create-account <account-name>`

### Passphrases

Wallet accounts can each be protected with a unique passphrase for additional security. The private keys are encrypted with the passphrase, so an attacker who gains access to your GLIF CLI Keystore cannot feasibly gain access to your account private keys. **It is strongly recommended to protect your wallet accounts with a secure passphrase**.

**Note that if you forget your passphrase, your private keys cannot be recovered. It is extremely important to write down your passphrase in a secure place where it cannot be stolen or lost.**

You can change your passphrase at any time by: <br />
`glif wallet change-passphrase <account-name>`<br />

### Migrate from a legacy keystore.toml wallet

If you're coming from an older version of this command line, you will have raw, unencrypted private keys stored in `~/.glif/keys.toml`. You will also not (yet) have an encrypted keystore. You can migrate to the new encrypted keystore by:<br />

`glif wallet migrate`

After you've migrated your wallet, we recommend testing a command or two to ensure the migration occurred smoothly. After the migration, you can safely remove your `keys.toml` file:<br />

`rm ~/.glif/keys.toml`

## Agents - Get started borrowing

The Agent is a crucial component of the underlying [GLIF Pools Protocol](https://glif.io/docs) (the Protocol on which the Infinity Pool is built) - the Agent is a wrapper contract around one or more [Miner Actors](https://github.com/filecoin-project/specs-actors/blob/master/actors/builtin/miner/miner_actor.go). The Agent is the Storage Provider's tool for interacting with the Pools as a Storage Provider. Soon, Agent commands will be available on our website.

### Create an Agent

If you haven't already, the first step in creating your Agent is to create the Agent wallet accounts:<br />

`glif wallet create-agent-accounts`

Next, you have to fund the owner key for your Agent to pay for gas. You can get your Agent's owner account with:<br />
`glif wallet list`

To fund your account, you can navigate over to the [GLIF Wallet](https://glif.io/wallet), and send some funds to your owner address. **IMPORTANT** - do NOT manually craft and send a `method 0` send transaction to an EVM address, passing it `value`. Use [fil-forwarder](https://docs.filecoin.io/smart-contracts/filecoin-evm-runtime/filforwader/) instead.

Once you've funded your owner key, verify:

```
➜ glif wallet balance

Agent accounts:

owner balance: 1.00 FIL
operator balance: 0.00 FIL
requester balance 0.00 FIL
```

The final step is to create your Agent:<br />
`glif agent create`<br />

If all goes successfully, you can run:<br />
`glif agent info`<br />

Which will print information about your Agent.

### Add a Miner to an Agent

Adding a Miner to your Agent requires the Agent to become the owner of your Miner. This process occurs in two steps:

1. Proposing an ownership change to your Miner Actor, passing your Agent's `f4` Filecoin address as the new owner.
2. Approving the ownership change from your Agent.

**Step 1 - Proposing an Ownership change**

This step occurs outside of GLIF and our command line. Depending on what mining software you use, this step will change. However, if you are running the `lotus-miner` command line, you can run the following command to propose the ownership change:<br />

`lotus-miner actor set-owner --really-do-it <agent-f410> <current-miner-owner>`<br />

Your Agent's `f4` address can be found by running `glif agent info` and inspecting the logs:

```
➜ glif agent info

BASIC INFO

...
Agent f4 Addr                         f410fh3njwnl6uirpnvi2o7qtnki43c47iyn5mf2q3nq
...
```

Once this transaction succeeds, you can proceed to step 2.

**Step 2 - Approving the ownership change**

Your Agent must approve the ownership change in order to complete the process of adding a Miner to your Agent. To approve the ownership change, run:<br />

`glif agent miners add <miner-id>`<br />

A single Agent can own more than 1 Miner, which increases the aggregate amount a Storage Provider can borrow under a single Agent.

### Borrow

Once your Agent has a Miner pledged to it, you can run `glif agent preview borrow-max` to get your maximum borrow amount. Note that this information is also available after running `glif agent info`.

When you decide how much to borrow, simply run:<br />
`glif agent borrow <amount>`<br />

Once the transaction confirms, the FIL will be available on your Agent smart contract. See the next section for how to push funds to one of your Agent's Miners.

**NOTE** - In order to borrow funds, your Agent must have made a payment back to the pool for _at least_ the fees it owes within the last 24 hours.

### Moving FIL from Miner to Agent and back

You can push funds directly from your Agent to a Miner owned by your Agent to use as pledge collateral on the Filecoin network:<br />
`glif agent miners push-funds <miner-id> <amount>`<br />

You can change your `~/.lotusminer/config.toml` to use available miner balance for sector collateral instead of sending it with each message:<br />

```
  # Whether to use available miner balance for sector collateral instead of sending it with each message
  #
  # type: bool
  # env var: LOTUS_SEALING_COLLATERALFROMMINERBALANCE
  #CollateralFromMinerBalance = false
```

When you want to pull funds up from your Miner to your Agent to withdraw rewards or make a weekly payment, you can use:<br />
`glif agent miners pull-funds <miner-id> <amount>`<br />

### Withdraw Rewards / Cash Advance

Sometimes you may need Filecoin to pay for gas or to sell on exchanges to pay for fiat denominated bills. In this case, you will want to withdraw funds off your Agent, and out of the GLIF Pools Protocol. You can do this when you have excess equity on your Agent - to read more about the economics, see our [docs](https://docs.glif.io/storage-provider-economics/withdraw-funds).

To withdraw funds from your Agent:<br />
`glif agent withdraw <amount> <receiver>`<br />

Remember that the `receiver` can be a named wallet account, so for example, you can withdraw funds to your Agent's owner key with:<br />

`glif agent withdraw <amount> owner`

### Remove a Miner from an Agent

You can remove a Miner from your Agent by calling `glif agent miners remove <miner-id> <new-owner-address>`. This call will propose an ownership change to the Agent's Miner, passing the `new-owner-address` as the proposed new owner. Once this transaction succeeds, you will need to approve the ownership change from the `new-owner-address`. It's important to note that this call will fail if you try to set an EVM actor as the new owner on a Miner.

It's important to note that removing a Miner from your Agent is removing equity, so this call may fail if you are economically not allowed to remove a Miner due to collateral requirements. The rules are treated identically to withdrawing funds from your Agent - you can read more about the economics [here](https://docs.glif.io/storage-provider-economics/withdraw-funds).

## Payments

After borrowing, Storage Providers are expected to make a payment once a week, for the amount of fees that have accrued throughout the given time period. You are not restricted to only make payments once a week - you can pay daily, every other day, or once a week. The amount of fees you pay does not depend on how frequently you choose to make payments.

To make a payment, your Agent must have sufficient balance on it (funds move from the Agent back into the pool):<br />
`glif agent pay <payment-type>`<br />

### Payment types

There are currently 3 types of payments:

1. `to-current` - pays only the current fees owed
2. `principal` - pays the current fees owed and a specific amount of principal
3. `custom` - pays a custom amount. If the amount is greater than the current owed fees, the rest of the payment is applied to principal.

Note that if you overpay principal, the overpayment amount is refunded to your Agent. So you cannot overpay on what you owe.

### Autopilot

It gets annoying to have to manually make payments each week - that's why we built autopilot. Autopilot is a service that automates: (1) pulling up funds from one of your Agent's Miners, and (2) making a payment back into the pool.

Autopilot's configuration settings can be found in `~/.glif/config.toml`. The default settings are as follows:

```
[autopilot]
# <to-current|principal|custom>
payment-type = 'to-current'
# amount is only required for 'principal' and 'custom' payment types
amount = 0
frequency = 5

[autopilot.pullfunds]
enabled = true
# to save on gas fees, pull the payment amount * pull-amount-factor
pull-amount-factor = 3
# miner that will have funds pulled from it
miner = '<miner-id>'
```

You can configure autopilot to whatever settings you'd like, and when you're ready to start the process, run:<br />
`glif agent autopilot`

### Leaving the pool

If you want to leave the pool for good, all you have to do is pay back all of your principal. We highly recommend using the command:<br />

`glif agent exit`<br />

As this will ensure _all_ the principal is paid off, and no tiny amounts of attofil remain borrowed.

## Agent health

It's important to note that an Agent can enter into an "unhealthy" state if it begins accruing faulty sectors and/or misses its weekly payment.

If your Agent has been marked in a faulty state, `glif agent info` will tell you. If you have recovered from your faulty state, you should recover your Agent's health using the command:<br />

`glif agent set-recovered`

## Advanced Mode

The GLIF CLI can be built in "advanced mode", which allows you to make ownership and administrative changes to your Agent. To build the CLI in advanced mode, run:<br />
`make advanced`<br />
`sudo make install`<br />

When run in advanced mode, you should be able to see the `glif agent admin` commands.

### Reset your Agent's owner key

### Reset your Agent's operator key

### Reset your Agent's requester key

When resetting your Agent's requester key, we will not be removing any old keys for safety purposes. Instead, we'll rename your current requester key and replace it with a new one. This is a 2 step process:

1. Recreate your `request` key by running:<br /> `glif agent admin create-key request`<br />Copy your new request key to use in step 2.
2. Change the `request` key on your Agent (this triggers an on-chain transaction):<br />`glif agent admin change-requester <new-request-key>`

Once the second transaction confirms on-chain, you should be good to go!
