import json
import pickle
from time import sleep
from threading import Lock, Thread

from Crypto.Cipher import AES
from Crypto.Hash import SHA512
from Crypto.Protocol.KDF import HKDF
from Crypto.PublicKey import ECC
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Util.Padding import pad, unpad
from web3.auto.infura.rinkeby import w3
from web3.exceptions import ContractLogicError, InvalidAddress, ValidationError


class Shared:
    account = None
    accounts = None
    contract = None
    running = True
    lock = Lock()


class Account:
    HKDF_SALT = bytes.fromhex("6e72d656a36f93aa6fbf1abedc0cc2a4dbf69f291659e5919005c8e854e29f9de1a61966f427fb8d15ac286a9d59a43c8b3d875fa3ab64d27dd73ef84724eb35")

    def __init__(self, private_key):
        self.account = w3.eth.account.from_key(private_key)

        key = ECC.generate(curve='P-256')
        self.public_key = int(key.pointQ.x), int(key.pointQ.y)
        self.private_key = int(key.d)

        if not self.register():
            self.change_public_key()

        self.automatic_response = False
        self.automatic_response_message = "Thank you for your message. I will reply as soon as possible.\n- {account.account.address}"

    def execute(self, function, *args):
        function_with_arguments = function(*args)

        return_value = function_with_arguments.call({"from": self.account.address})

        if function_with_arguments.abi["stateMutability"] in ("nonpayable", "payable"):
            transaction = function_with_arguments.buildTransaction({
                "gas": 3000000,
                "nonce": w3.eth.getTransactionCount(self.account.address),
            })
            transaction_signed = self.account.sign_transaction(transaction)
            transaction_hash = w3.eth.sendRawTransaction(transaction_signed.rawTransaction)
            w3.eth.waitForTransactionReceipt(transaction_hash, timeout=600)

        return return_value

    def register(self):
        print("Registering with contract...")
        try:
            self.execute(Shared.contract.functions.register, self.public_key)
            print("Registration successful.")
            return True
        except ContractLogicError:  # Already registered.
            print("Already registered.")
            return False

    def change_public_key(self):
        print("Changing contract public key...")
        self.execute(Shared.contract.functions.changePublicKey, self.public_key)
        print("Key changed successfully.")

    def set_friend_state(self, friend, state):
        print("Changing friend state...")
        try:
            self.execute(Shared.contract.functions.setFriendState, friend, state)
            print("Friend state changed successfully.")
        except (InvalidAddress, ValidationError):
            print("Invalid address.")

    def get_public_key(self, member):
        print("Getting member public key...")
        try:
            return self.execute(Shared.contract.functions.getPublicKey, member)
        except (InvalidAddress, ValidationError):
            print("Invalid member address.")
            return None

    def encrypt(self, member, data):
        member_public_key = self.get_public_key(member)
        if member_public_key is None:
            return None, None

        data = pad(data.encode(), 16)

        print("Generating shared key...")

        member_public_key = ECC.EccPoint(*member_public_key, curve='P-256')
        message_key = ECC.generate(curve='P-256')

        shared_secret = long_to_bytes((member_public_key * message_key.d).x)
        shared_key = HKDF(shared_secret, 16, Account.HKDF_SALT, SHA512)

        print("Encrypting message...")

        cipher = AES.new(shared_key, AES.MODE_GCM)

        ciphertext = cipher.encrypt(data)

        return (int(message_key.pointQ.x), int(message_key.pointQ.y)), [cipher.nonce] + [ciphertext[i:i + 16] for i in range(0, len(ciphertext), 16)]

    def message(self, to, public_key, blocks):
        print("Sending message...")
        try:
            self.execute(Shared.contract.functions.message, to, public_key, blocks)
            print("Message sent successfully.")
        except (InvalidAddress, ValidationError):
            print("Invalid to address.")

    def get_owner(self):
        print("Getting owner address...")
        return self.execute(Shared.contract.functions.getOwner)

    def message_owner(self, public_key, blocks):
        print("Sending message...")
        try:
            self.execute(Shared.contract.functions.messageOwner, public_key, blocks)
            print("Message sent successfully.")
        except ContractLogicError:
            print("Not enough funds for processing fee.")

    def decrypt(self, message_public_key, blocks):
        message_public_key = ECC.EccPoint(*message_public_key, curve='P-256')

        shared_secret = long_to_bytes((message_public_key * self.private_key).x)
        shared_key = HKDF(shared_secret, 16, Account.HKDF_SALT, SHA512)

        nonce = blocks[0]
        ciphertext = b"".join(blocks[1:])

        cipher = AES.new(shared_key, AES.MODE_GCM, nonce=nonce)

        return unpad(cipher.decrypt(ciphertext), 16).decode()


def save_accounts():
    with open("iirc.pickle", "wb") as f:
        pickle.dump(Shared.accounts, f)


def add_account(private_key):
    print("Adding account...")

    Shared.accounts.append(Account(private_key))

    save_accounts()

    print("Account added successfully.")


def list_accounts():
    if Shared.accounts:
        for index, account in enumerate(Shared.accounts):
            print(f"{index}: {account.account.address}")
    else:
        print("There are no accounts. You can add one using \"add_account\".")


def account():
    if Shared.account is not None:
        return Shared.accounts[Shared.account]
    else:
        print("No account is selected. You can select one using \"set_account\".")
        return None


def get_account():
    account_ = account()
    if account_ is not None:
        print(f"{Shared.account}: {account_.account.address}")


def set_account(index):
    if index < len(Shared.accounts):
        Shared.account = index
    else:
        print("Invalid index. You can list accounts with \"list_accounts\".")


def set_friend_state(friend, state):
    account_ = account()
    if account_ is not None:
        account_.set_friend_state(friend, state)


def message(to, data):
    account_ = account()
    if account_ is None:
        return None

    public_key, blocks = account_.encrypt(to, data)
    if public_key is None or blocks is None:
        return None

    account_.message(to, public_key, blocks)


def message_owner(data):
    account_ = account()
    if account_ is None:
        return None

    public_key, blocks = account_.encrypt(account_.get_owner(), data)
    if public_key is None or blocks is None:
        return None

    account_.message_owner(public_key, blocks)


def set_automatic_response_state(state):
    account_ = account()
    if account_ is None:
        return None

    if account_.automatic_response != state:
        account_.automatic_response = state

        save_accounts()


def set_automatic_response(message):
    account_ = account()
    if account_ is None:
        return None

    if account_.automatic_response_message != message:
        account_.automatic_response_message = message

        save_accounts()


def exit_():
    Shared.running = False


HELP_TEXT = """
Account management:
    add_account <private_key> - Add an account using an Etherium private key.
    list_accounts - List all account indexes and addresses.
    get_account - Get the current account index and address.
    set_account <index> - Sets the current account.

Friendships:
    add_friend <address> - Adds an address to your list of friends.
    remove_friend <address> - Removes an address from your list of friends.

Messaging:
    message <address> <message> - Sends a message to the given address.
    message_owner <message> - Sends a message to the contract owner. Requires a small processing fee.
    enable_automatic_response - Enables automatic responses.
    disable_automatic_response - Disables automatic responses.
    set_automatic_response <message> - Sets the automatic response message. The placeholder {account.account.address} can be used instead of your account address.

IIRC token management:
    // TODO
    
Miscellaneous:
    exit - Exits the client.
    help - Displays this text.
"""


COMMANDS = {
    "add_account": ((str,), add_account),
    "list_accounts": (tuple(), list_accounts),
    "get_account": (tuple(), get_account),
    "set_account": ((int,), set_account),
    "add_friend": ((str,), lambda friend: set_friend_state(friend, True)),
    "remove_friend": ((str,), lambda friend: set_friend_state(friend, False)),
    "message": ((str, str), message),
    "message_owner": ((str,), message_owner),
    "enable_automatic_response": (tuple(), lambda: set_automatic_response_state(True)),
    "disable_automatic_response": (tuple(), lambda: set_automatic_response_state(False)),
    "set_automatic_response": ((str,), set_automatic_response),
    "exit": (tuple(), exit_),
    "help": (tuple(), lambda: print(HELP_TEXT)),
}


def foreground():
    with Shared.lock:
        print("Loading smart contract...")
        with open("iirc.json") as f:
            Shared.contract = w3.eth.contract("0xF625AE3A94801E476a224A9aB117ca9F6e442743", abi=json.load(f))

        print("Loading accounts...")
        try:
            with open("iirc.pickle", "rb") as f:
                Shared.accounts = pickle.load(f)
        except FileNotFoundError:
            Shared.accounts = []

    while Shared.running:
        input_ = input("> ").strip().split()

        if len(input_) == 0:
            print("You must enter a command. Enter \"help\" for a list of commands.")
            continue

        if input_[0] not in COMMANDS:
            print("Invalid command. Enter \"help\" for a list of commands.")
            continue

        command = COMMANDS[input_[0]]

        if input_[0] == "message" and len(input_) > 3:
            input_ = input_[:2] + [" ".join(input_[2:])]

        if input_[0] in ("message_owner", "set_automatic_response") and len(input_) > 2:
            input_ = [input_[0], " ".join(input_[1:])]

        if len(input_) - 1 != len(command[0]):
            print("Incorrect number of arguments. Enter \"help\" for a list of commands.")
            continue

        try:
            with Shared.lock:
                command[1](*(type_(value) for type_, value in zip(command[0], input_[1:])))
        except Exception as e:
            print("An error occurred:", repr(e))


def background():
    from_block = w3.eth.block_number

    while Shared.running:
        sleep(15)

        with Shared.lock:
            if Shared.account is None or Shared.contract is None:
                continue

            account_ = account()
            if account_ is None:
                continue

            try:
                logs = w3.eth.get_logs({
                    "fromBlock": from_block,
                    "address": Shared.contract.address,
                    "topics": [
                        "0x5c640cddf0cd2eec63278ce12860a658f1edfb6554a96a9b84316fd5e8818c25",
                        None,
                        f"""0x{account_.account.address[2:].rjust(64, "0")}"""
                    ]
                })
            except Exception as e:
                print("An error occurred while getting logs: ", repr(e))
                print("> ", end="")
                continue

            for event in logs:
                from_block = max(from_block, event.blockNumber + 1)

                print("")

                try:
                    from_ = w3.toChecksumAddress(event.topics[1][12:].hex())
                    data = bytes.fromhex(event.data[2:])
                    message_public_key = (bytes_to_long(data[0:32]), bytes_to_long(data[32:64]))
                    blocks = [data[i:i + 16] for i in range(128, len(data), 32)]

                    message_ = account_.decrypt(message_public_key, blocks)

                    print(f"Message from {from_}:")
                    print(message_)

                    if account_.automatic_response and not message_.startswith("#"):  # Stop response loops.
                        message_ = "# " + message_.replace("\n", "\n# ") + "\n" + account_.automatic_response_message
                        message_ = message_.format(account=account_)

                        print("Sending automatic response...")
                        message(from_, message_)
                except Exception as e:
                    print("An error occurred while processing a message:", repr(e))

                print("> ", end="")


def main():
    foreground_ = Thread(target=foreground)
    background_ = Thread(target=background)

    foreground_.start()
    background_.start()

    foreground_.join()
    background_.join()


if __name__ == '__main__':
    main()
