# Challenge

## Briefing

We have identified that two criminals are communicating using a smart contract based messaging system. One has the address `0x76D9806BaB71799B8Bff4334018a69cFCED92aA0` and the other has the address `0x8A7Ff03D175Fd00462EA737eC08f2385859d9a4F`.

We have obtained a copy of the client used to connect to the system. Both criminals keep their clients open at all times and make use of the automatic reply feature.

Can you decode the secret messages?

## Required Files

- `iirc.py`
- `iirc.json`

## Optional Files

- `IIRC.sol` - This is the source code of the smart contract. The challenge is possible without it but much easier with it.

## Additional Information

You will need the `pycryptodome` and `web3` packages for the client to work. You will also need [Infura](https://infura.io/) API credentials.

The contract is hosted on the Rinkeby testnet. You can get funds for the testnet at [https://faucet.rinkeby.io/](https://faucet.rinkeby.io/).

If you don't want spoilers, don't look at `writeup.md` or `solve.py`.

The purpose of this challenge is NOT to take control of any accounts. This is probably possible - please don't do it though.

