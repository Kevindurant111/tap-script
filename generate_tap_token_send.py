import argparse
import hashlib
from bitcoinutils.setup import setup
from bitcoinutils.transactions import Transaction, TxInput, TxOutput, TxWitnessInput
from bitcoinutils.keys import PrivateKey, PublicKey, Address
from bitcoinutils.script import Script
from bitcoinutils.utils import to_satoshis

def tagged_hash(tag, data):
    tag_hash = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(tag_hash + tag_hash + data).digest()

def get_unspendable_pubkey():
    # Compute the NUMS point x-coordinate as per BIP341 recommendation
    zero_bytes = b'\x00' * 32
    tweak = tagged_hash("TapTweak", zero_bytes)
    x = int.from_bytes(tweak, 'big') % (2**256 - 1)  # Simplified, actual lift_x needed for valid point
    # Known x for unspendable key (even y)
    unspendable_x_hex = '50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0'
    return PublicKey.from_x_only_hex(unspendable_x_hex)

def chunk_content(content_bytes, chunk_size=520):
    return [content_bytes[i:i + chunk_size] for i in range(0, len(content_bytes), chunk_size)]

def generate_tap_token_send_tx(input_txid, input_vout, input_privkey_wif, input_value_sat, wallet_address, token_name, amount, receiver_address, fee_sat, commit_value_sat=546, network='mainnet'):
    setup(network)

    # Private and public key for signing (if provided)
    priv = PrivateKey.from_wif(input_privkey_wif) if input_privkey_wif else None
    pub = priv.get_public_key() if priv else None

    # Create the inscription content
    content = f'{{"p":"tap","op":"token-send","items":[{{"tick":"{token_name}","amt":"{amount}","address":"{receiver_address}"}}]}}'
    content_bytes = content.encode('utf-8')
    content_pushes = chunk_content(content_bytes)

    # Inscription envelope script
    mime = 'text/plain;charset=utf-8'
    inscription_script = Script(['OP_FALSE', 'OP_IF', 'ord', 'OP_1', mime, 'OP_0'] + content_pushes + ['OP_ENDIF'])

    # Get unspendable internal pubkey
    unspendable_pub = get_unspendable_pubkey()

    # Create Taproot address for commit
    taproot_address = unspendable_pub.get_taproot_address(inscription_script)

    # Create transaction
    change_value = input_value_sat - commit_value_sat - fee_sat
    if change_value < 0:
        raise ValueError("Insufficient funds for transaction")

    txin = TxInput(input_txid, input_vout)
    commit_out = TxOutput(commit_value_sat, taproot_address.to_script_pub_key())
    change_out = TxOutput(change_value, Address.from_string(wallet_address).to_script_pub_key())
    tx = Transaction([txin], [commit_out, change_out], has_segwit=True)

    # Unsigned transaction hex
    unsigned_tx_hex = tx.serialize()

    # Sign transaction if private key is provided
    signed_tx_hex = None
    if priv:
        sig = priv.sign_segwit_input(tx, 0, pub.get_segwit_address().to_script_pub_key(), input_value_sat)
        tx.witnesses.append(TxWitnessInput([sig, pub.to_hex(True)]))
        signed_tx_hex = tx.serialize()

    return unsigned_tx_hex, signed_tx_hex

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate Bitcoin transaction for TAP token send")
    parser.add_argument("--wallet_address", required=True, help="Local wallet address for change")
    parser.add_argument("--receiver_address", required=True, help="Receiver's Bitcoin address in inscription")
    parser.add_argument("--token_name", required=True, help="Name of the TAP token (tick)")
    parser.add_argument("--amount", required=True, help="Amount of token to send")
    parser.add_argument("--input_txid", required=True, help="TXID of the input UTXO")
    parser.add_argument("--input_vout", type=int, required=True, help="Vout of the input UTXO")
    parser.add_argument("--input_privkey_wif", help="Private key WIF of the input (optional for unsigned tx)")
    parser.add_argument("--input_value_sat", type=int, required=True, help="Value of the input UTXO in satoshis")
    parser.add_argument("--fee_sat", type=int, default=1000, help="Fee for transaction in satoshis")
    parser.add_argument("--network", default="mainnet", choices=["mainnet", "testnet"], help="Bitcoin network")

    args = parser.parse_args()

    unsigned_hex, signed_hex = generate_tap_token_send_tx(
        args.input_txid, args.input_vout, args.input_privkey_wif, args.input_value_sat,
        args.wallet_address, args.token_name, args.amount, args.receiver_address,
        args.fee_sat, network=args.network
    )

    print("Unsigned Transaction Hex:")
    print(unsigned_hex)
    if signed_hex:
        print("\nSigned Transaction Hex:")
        print(signed_hex)
    print("\nInstructions: Broadcast the signed transaction to inscribe the TAP token send. The output UTXO can then be spent by the sender address to confirm the transfer.")