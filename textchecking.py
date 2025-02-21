from PIL import Image
import numpy as np


def text_to_bits(text):
    bits = bin(int.from_bytes(text.encode(), 'big'))[2:]
    return bits.zfill(8 * ((len(bits) + 7) // 8))


def bits_to_text(bits, encoding='utf-8'):
    n = int(bits, 2)
    return n.to_bytes((n.bit_length() + 7) // 8, 'big').decode(encoding, errors='ignore')



def encode_text(image_path, text):
    img = Image.open(image_path)
    width, height = img.size
    binary_text = text_to_bits(text)
    # Padding with zeros to match image size
    binary_text += '0' * ((width * height * 3) - len(binary_text))

    pixel_values = list(img.getdata())
    new_pixels = []
    text_index = 0

    for pixel in pixel_values:
        new_pixel = []
        for value in pixel:
            if text_index < len(binary_text):
                new_value = value & ~1 | int(binary_text[text_index])
                text_index += 1
            else:
                new_value = value
            new_pixel.append(new_value)
        new_pixels.append(tuple(new_pixel))

    new_img = Image.new('RGB', (width, height))
    new_img.putdata(new_pixels)
    new_img.save('encoded_image.png')


def decode_text(image_path):
    img = Image.open(image_path)
    pixel_values = list(img.getdata())
    binary_text = ''

    for pixel in pixel_values:
        for value in pixel:
            binary_text += bin(value)[-1]

    return bits_to_text(binary_text)


# Example usage
text = "This is a hidden message."
encode_text("two.png", text)
decoded_text = decode_text("encoded_image.png")
print("Decoded text:", decoded_text)
