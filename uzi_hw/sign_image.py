"""Program to digitally sign an image and embed the signature."""

import hashlib
from PIL import Image
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

PRIVATE_KEY_PATH = "keys/private_key.pem"
INPUT_IMAGE_PATH = "image/secret.png"
OUTPUT_SIGNED_IMAGE_PATH = "image/signed.png"
TEMP_DATA_PATH = "image/original_data.bin"

def load_private_key():
    """Load the private key from a file."""
    with open(PRIVATE_KEY_PATH, "rb") as private_key_file:
        return serialization.load_pem_private_key(
            private_key_file.read(),
            password=None
        )

def save_original_image_data(image_path):
    """Save original image data for signing."""
    with Image.open(image_path) as image:
        if image.mode != 'RGB':
            image = image.convert('RGB')
        image_data = image.tobytes()

    with open(TEMP_DATA_PATH, 'wb') as temp_file:
        temp_file.write(image_data)

    return hashlib.sha256(image_data).digest()

def embed_signature_into_image(image_path, signature_bytes, original_hash, output_path):
    """Embed the signature and hash into the image using LSB steganography."""
    with Image.open(image_path) as image:
        if image.mode != 'RGB':
            image = image.convert('RGB')

        width, height = image.size
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
            if pixel_x >= width:
                pixel_x = 0
                pixel_y += 1

        pixel_x, pixel_y = 0, 16
        for byte in data_to_embed:
            for bit in format(byte, '08b'):
                red_channel, green_channel, blue_channel = pixel_data[pixel_x, pixel_y]
                red_channel = (red_channel & ~1) | int(bit)
                pixel_data[pixel_x, pixel_y] = (red_channel, green_channel, blue_channel)

                pixel_x += 1
                if pixel_x >= width:
                    pixel_x = 0
                    pixel_y += 1
                    if pixel_y >= height:
                        raise ValueError("Image too small to embed all data.")

        image.save(output_path, "PNG", compress_level=0)

def sign_image():
    """Sign an image and embed the signature."""
    print(f"Signing image {INPUT_IMAGE_PATH}...")
    try:
        original_image_hash = save_original_image_data(INPUT_IMAGE_PATH)
        private_key = load_private_key()

        signature = private_key.sign(
            original_image_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        embed_signature_into_image(INPUT_IMAGE_PATH, signature, original_image_hash, OUTPUT_SIGNED_IMAGE_PATH)
        print(f"Image successfully signed and saved to {OUTPUT_SIGNED_IMAGE_PATH}.")

    except Exception as error:
        print(f"Error during signing: {error}")

def main():
    """Main function for image signing."""
    sign_image()

if __name__ == "__main__":
    main()