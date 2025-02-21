from PIL import Image

def encode_image(cover_image_path, secret_image_path, output_image_path):
    # Open the cover image and secret image
    cover_image = Image.open(cover_image_path)
    secret_image = Image.open(secret_image_path)

    # Resize the secret image to fit inside the cover image
    secret_image = secret_image.resize(cover_image.size)

    # Convert images to RGB mode
    cover_image = cover_image.convert("RGB")
    secret_image = secret_image.convert("RGB")

    # Extract pixel data from images
    cover_pixels = cover_image.load()
    secret_pixels = secret_image.load()

    # Embed secret image into cover image using LSB replacement
    for x in range(cover_image.width):
        for y in range(cover_image.height):
            cover_pixel = list(cover_pixels[x, y])
            secret_pixel = list(secret_pixels[x, y])

            # Replace least significant bits of cover pixel values with secret pixel values
            for i in range(3):  # R, G, B channels
                cover_pixel[i] = (cover_pixel[i] & 0xFE) | ((secret_pixel[i] >> 7) & 1)  # Replace LSB of cover pixel

            # Update cover image pixel with modified pixel values
            cover_pixels[x, y] = tuple(cover_pixel)

    # Save the modified cover image with the embedded secret image
    cover_image.save(output_image_path)
    print("Image encoded successfully.")

def decode_image(encoded_image_path, output_image_path):
    # Open the encoded image
    encoded_image = Image.open(encoded_image_path)

    # Create a new image to store the decoded secret image
    decoded_image = Image.new("RGB", encoded_image.size)
    decoded_pixels = decoded_image.load()

    # Extract secret image from encoded image using LSB replacement
    for x in range(encoded_image.width):
        for y in range(encoded_image.height):
            encoded_pixel = list(encoded_image.getpixel((x, y)))
            decoded_pixel = [0, 0, 0]

            # Extract LSBs from encoded pixel to obtain secret pixel values
            for i in range(3):  # R, G, B channels
                decoded_pixel[i] = encoded_pixel[i] & 1  # Extract LSB from each channel

            # Convert the binary pixel values back to integer values (0 or 255)
            decoded_pixel = [0 if bit == 0 else 255 for bit in decoded_pixel]

            # Update decoded image pixel with secret pixel values
            decoded_pixels[x, y] = tuple(decoded_pixel)

    # Save the decoded secret image
    decoded_image.save(output_image_path)
    print("Image decoded successfully.")

# Example usage
cover_image_path = "capture.png"
secret_image_path = "one.png"
output_image_path = "encoded_image.png"

# Encode the secret image into the cover image
encode_image(cover_image_path, secret_image_path, output_image_path)

# Decode the secret image from the encoded image
decoded_output_image_path = "decoded_image.png"
decode_image(output_image_path, decoded_output_image_path)
