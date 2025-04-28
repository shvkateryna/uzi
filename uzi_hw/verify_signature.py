"""Program to verify a digital signature embedded in an image."""

from PIL import Image
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

PUBLIC_KEY_PATH = "keys/public_key.pem"
SIGNED_IMAGE_PATH = "image/signed.png"

def load_public_key():
    """Load the public key from a file."""
    with open(PUBLIC_KEY_PATH, "rb") as public_key_file:
        return serialization.load_pem_public_key(public_key_file.read())

def extract_signature_and_hash(image_path):
    """Extract the embedded hash and signature from the image."""
    with Image.open(image_path) as image:
        if image.mode != 'RGB':
            image = image.convert('RGB')

        width, height = image.size
        pixel_data = image.load()

        data_length_binary = ""
        pixel_x, pixel_y = 0, 0
        for _ in range(16):
            red_channel, _, _ = pixel_data[pixel_x, pixel_y]
            data_length_binary += str(red_channel & 1)
            pixel_x += 1
            if pixel_x >= width:
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
            if pixel_y >= height:
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
            if pixel_x >= width:
                pixel_x = 0
                pixel_y += 1

        if len(extracted_bytes) >= 32:
            return bytes(extracted_bytes[:32]), bytes(extracted_bytes[32:])

        return None

def verify_image_signature():
    """Verify the embedded digital signature in the image."""
    print(f"Verifying signature in {SIGNED_IMAGE_PATH}...")
    try:
        extracted_data = extract_signature_and_hash(SIGNED_IMAGE_PATH)
        if extracted_data is None:
            print("No valid embedded signature data found in the image.")
            return

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

        print("Signature verification successful. The image is authentic!")

    except Exception as error:
        print(f"Signature verification failed: {error}")

def main():
    """Main function for verifying an image signature."""
    verify_image_signature()

if __name__ == "__main__":
    main()
