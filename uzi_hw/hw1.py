"""Image signing and verification using LSB steganography and RSA signatures."""

import hashlib
import os
from PIL import Image
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

PRIVATE_KEY_PATH = "keys/private_key.pem"
PUBLIC_KEY_PATH = "keys/public_key.pem"
INPUT_IMAGE_PATH = "image/secret.png"
OUTPUT_SIGNED_PATH = "image/signed.png"
TEMP_DATA_PATH = "image/original_data.bin"

def load_private_key():
    """Load the private key from a file."""
    with open(PRIVATE_KEY_PATH, "rb") as private_key_file:
        return serialization.load_pem_private_key(
            private_key_file.read(),
            password=None
        )

def load_public_key():
    """Load the public key from a file."""
    with open(PUBLIC_KEY_PATH, "rb") as public_key_file:
        return serialization.load_pem_public_key(public_key_file.read())

def calculate_image_hash(image_path):
    """Calculate the SHA-256 hash of the image data."""
    with Image.open(image_path) as image:
        if image.mode != 'RGB':
            image = image.convert('RGB')
        image_data = image.tobytes()
    return hashlib.sha256(image_data).digest()

def save_original_data(image_path):
    """Save original image data for future verification."""
    with Image.open(image_path) as image:
        if image.mode != 'RGB':
            image = image.convert('RGB')
        image_data = image.tobytes()

    with open(TEMP_DATA_PATH, 'wb') as temp_file:
        temp_file.write(image_data)

    return hashlib.sha256(image_data).digest()

def embed_signature(image_path, signature_bytes, original_hash, output_path):
    """Embed the binary signature data into an image using LSB steganography."""
    with Image.open(image_path) as image:
        if image.mode != 'RGB':
            image = image.convert('RGB')

        image_width, image_height = image.size
        pixel_data = image.load()

        data_to_embed = original_hash + signature_bytes
        data_length = len(data_to_embed)
        data_length_binary = format(data_length, '016b')

        pixel_x, pixel_y = 0, 0
        for bit in data_length_binary:
            red_channel, green_channel, blue_channel = pixel_data[pixel_x, pixel_y]
            red_channel = (red_channel & ~1) | int(bit)
            pixel_data[pixel_x, pixel_y] = (red_channel, green_channel, blue_channel)
            pixel_x += 1
            if pixel_x >= image_width:
                pixel_x = 0
                pixel_y += 1

        pixel_x, pixel_y = 0, 16
        for byte in data_to_embed:
            for bit in format(byte, '08b'):
                red_channel, green_channel, blue_channel = pixel_data[pixel_x, pixel_y]
                red_channel = (red_channel & ~1) | int(bit)
                pixel_data[pixel_x, pixel_y] = (red_channel, green_channel, blue_channel)

                pixel_x += 1
                if pixel_x >= image_width:
                    pixel_x = 0
                    pixel_y += 1
                    if pixel_y >= image_height:
                        raise ValueError("Image too small to embed all data.")

        image.save(output_path, "PNG", compress_level=0)

def extract_data(image_path):
    """Extract embedded binary data from an image."""
    with Image.open(image_path) as image:
        if image.mode != 'RGB':
            image = image.convert('RGB')

        image_width, image_height = image.size
        pixel_data = image.load()

        data_length_binary = ""
        pixel_x, pixel_y = 0, 0
        for _ in range(16):
            red_channel, _, _ = pixel_data[pixel_x, pixel_y]
            data_length_binary += str(red_channel & 1)
            pixel_x += 1
            if pixel_x >= image_width:
                pixel_x = 0
                pixel_y += 1

        try:
            data_length = int(data_length_binary, 2)
        except ValueError:
            return None

        pixel_x, pixel_y = 0, 16
        total_bits = data_length * 8
        bits_extracted = 0

        extracted_bytes = bytearray()
        current_byte_bits = ""

        while bits_extracted < total_bits:
            if pixel_y >= image_height:
                break

            red_channel, _, _ = pixel_data[pixel_x, pixel_y]
            current_byte_bits += str(red_channel & 1)

            if len(current_byte_bits) == 8:
                try:
                    extracted_bytes.append(int(current_byte_bits, 2))
                except ValueError:
                    return None
                current_byte_bits = ""

            bits_extracted += 1
            pixel_x += 1
            if pixel_x >= image_width:
                pixel_x = 0
                pixel_y += 1

        if len(extracted_bytes) >= 32:
            return bytes(extracted_bytes[:32]), bytes(extracted_bytes[32:])

        return None

def sign_image():
    """Sign an image and embed the signature."""
    print(f"Signing image {INPUT_IMAGE_PATH}...")
    try:
        original_image_hash = save_original_data(INPUT_IMAGE_PATH)
        private_key = load_private_key()
        signature = private_key.sign(
            original_image_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        embed_signature(INPUT_IMAGE_PATH, signature, original_image_hash, OUTPUT_SIGNED_PATH)
        print(f"Image successfully signed and saved to {OUTPUT_SIGNED_PATH}.")
        return True
    except Exception as error:
        print(f"Error signing image: {error}")
        return False

def verify_signature():
    """Verify the signature embedded in an image."""
    print(f"Verifying signature for {OUTPUT_SIGNED_PATH}...")
    try:
        extracted_data = extract_data(OUTPUT_SIGNED_PATH)
        if extracted_data is None:
            print("No valid signature data found in image.")
            return False

        original_image_hash, extracted_signature = extracted_data
        public_key = load_public_key()

        public_key.verify(
            extracted_signature,
            original_image_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        print("Signature successfully verified!")
        return True

    except Exception as error:
        print(f"Signature verification failed: {error}")
        return False

def main():
    """Main function to sign and verify an image."""
    print("Image Signing and Verification Tool")
    print("==================================")

    print("\n1. Signing the image...")
    sign_image()

    print("\n2. Verifying the image...")
    verify_signature()

    if os.path.exists(TEMP_DATA_PATH):
        os.remove(TEMP_DATA_PATH)

if __name__ == "__main__":
    main()
