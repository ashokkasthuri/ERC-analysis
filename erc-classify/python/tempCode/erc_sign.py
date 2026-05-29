'''
Author: ashokkasthuri ashokk@smu.edu.sg
Date: 2025-04-25 16:17:45
LastEditors: ashokkasthuri ashokk@smu.edu.sg
LastEditTime: 2025-04-28 10:46:35
FilePath: /ERC-analysis-master/erc-classify/erc_sign.py
Description: 这是默认设置,请设置`customMade`, 打开koroFileHeader查看配置 进行设置: https://github.com/OBKoro1/koro1FileHeader/wiki/%E9%85%8D%E7%BD%AE
'''
from eth_account import Account
from eth_account.messages import encode_defunct
from web3 import Web3
import os
from dotenv import load_dotenv

def pad_hex(value):
    """Convert any signature component to properly padded hex string"""
    if isinstance(value, bytes):
        hex_str = value.hex()
    elif isinstance(value, int):
        hex_str = hex(value)[2:]  # Convert int to hex and remove 0x
    elif isinstance(value, str):
        hex_str = value[2:] if value.startswith("0x") else value
    else:
        raise ValueError(f"Unsupported type for hex conversion: {type(value)}")
    
    return '0x' + hex_str.zfill(64)  # Pad to 64 hex characters (32 bytes)

# Load environment variables
load_dotenv()
private_key = os.getenv('METAMASK_PRIVATE_KEY')

if not private_key:
    raise ValueError("METAMASK_PRIVATE_KEY not found in .env file")

# Your digest
digest = "0x29ea703be2f5f83d7d4469a05e251370786f661d223dd59da049e8f20561c526"

try:
    # Sign the message
    message = encode_defunct(hexstr=digest)
    signed_message = Account.sign_message(message, private_key)

    # Get components
    v = signed_message.v  # This is an integer
    r = signed_message.r  # This may be bytes or int depending on version
    s = signed_message.s  # This may be bytes or int depending on version

    # Format all components
    v_hex = hex(v)
    r_hex = pad_hex(r)
    s_hex = pad_hex(s)

    print("✅ Properly formatted values for Remix:")
    print(f"v: {v} (or {v_hex} in hex)")
    print(f"r: {r_hex}")  # 66 chars (with 0x)
    print(f"s: {s_hex}")  # 66 chars (with 0x)
    print(f"📝 Full signature: {signed_message.signature.hex()}")

except Exception as e:
    print(f"❌ Error during signing: {str(e)}")
    if "invalid hexlify input" in str(e):
        print("⚠️ Make sure your private key is 64 hex characters (with or without 0x prefix)")