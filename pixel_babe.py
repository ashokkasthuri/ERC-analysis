from PIL import Image
import numpy as np
import random

def generate_sample_image(width=10, height=10, filename="sample_10x10.png"):
    """Generate a 10x10 sample image with random colors."""
    img = Image.new("RGB", (width, height))
    pixels = img.load()
    
    for i in range(width):
        for j in range(height):
            r = random.randint(0, 255)
            g = random.randint(0, 255)
            b = random.randint(0, 255)
            pixels[i, j] = (r, g, b)
    
    img.save(filename)
    print(f"Sample image saved as '{filename}'")
    return img

def text_to_binary(text):
    """Convert text to 8-bit binary."""
    return ''.join(format(ord(c), '08b') for c in text)

def encode_text_in_pixels(image_path, output_path, text):
    """Encode text into every pixel of the image."""
    img = Image.open(image_path)
    pixels = np.array(img)
    binary_text = text_to_binary(text)
    
    # Repeat "hi" for every pixel (100 times)
    repeated_binary = binary_text * (img.width * img.height)
    
    index = 0
    for i in range(img.width):
        for j in range(img.height):
            r, g, b = pixels[j, i]
            
            # Modify LSB (Least Significant Bit) of each channel
            if index < len(repeated_binary):
                r = (r & 0xFE) | int(repeated_binary[index])
                index += 1
            if index < len(repeated_binary):
                g = (g & 0xFE) | int(repeated_binary[index])
                index += 1
            if index < len(repeated_binary):
                b = (b & 0xFE) | int(repeated_binary[index])
                index += 1
            
            pixels[j, i] = [r, g, b]
    
    encoded_img = Image.fromarray(pixels)
    encoded_img.save(output_path)
    print(f"Encoded image saved as '{output_path}'")

def decode_text_from_pixels(image_path, expected_length=2):
    """Decode text hidden in every pixel."""
    img = Image.open(image_path)
    pixels = np.array(img)
    binary = ""
    
    for i in range(img.width):
        for j in range(img.height):
            r, g, b = pixels[j, i]
            binary += str(r & 1)  # Extract LSB of R
            binary += str(g & 1)  # Extract LSB of G
            binary += str(b & 1)  # Extract LSB of B
    
    # Extract the first 'expected_length' characters
    decoded_text = ""
    for i in range(0, expected_length * 8, 8):
        byte = binary[i:i+8]
        decoded_text += chr(int(byte, 2))
    
    return decoded_text

def main():
    # Step 1: Generate a sample 10x10 image
    # generate_sample_image()
    
    # Step 2: Encode "hi" into every pixel
    hi = "This paper presents the first large-scale empirical study of Ethereum Request for Comment (ERC) standards, combining systematic classification with security vulnerability detection across four million Ethereum Virtual Machine (EVM) smart contracts. We introduce Target Block, a novel program analysis tool that automates ERC classification by enforcing mandatory specifications from Ethereum documentation. Leveraging static analysis of both source code and bytecode, along with control-flow graph (CFG) construction for granular function-level inspection, we rigorously evaluate compliance with ERC constraints and uncover critical security flaws.Our analysis reveals pervasive vulnerabilities in key ERC implementations, notably in ERC5267 and ERC2612, where the omission of salt in DOMAIN-SEPARATOR construction violates the domain separation principle of EIP-712. This flaw enables cross-contract signature replay attacks: identically deployed contracts generate identical domain separators, allowing adversaries to reuse signatures across instances. Worse, attackers can exploit this weakness to bypass security measures during contract upgrades or deploy malicious clones, undermining multi-chain interoperability. We further identify silent signature verification failures and type hash mismatches, which risk invalidating legitimate transactions while accepting unauthorized ones. Our findings demonstrate that these vulnerabilities persist across major blockchains (Ethereum, Polygon, Binance Smart Chain, and Avalanche), exposing systemic gaps in ERC adherence. By quantifying these risks and providing a taxonomy of ERC-specific security flaws, this work establishes a foundational framework for secure smart contract development. The Target Block tool and our empirical dataset are released to foster future research. This study not only bridges a critical gap in blockchain security literature but also urges the adoption of standardized safeguards for ERC implementations, with immediate implications for auditors, developers, and protocol designers"
    
    encode_text_in_pixels("logo_s.png", "encoded_image.png", hi)
    
    # Step 3: Decode the hidden message
    # decoded_message = decode_text_from_pixels("encoded_image.png", 2)
    # print(f"Decoded message from each pixel: '{decoded_message}'")

if __name__ == "__main__":
    main()