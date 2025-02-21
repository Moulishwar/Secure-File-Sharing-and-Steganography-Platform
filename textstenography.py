from PIL import Image

def encode_message(image_path, message):
    # Open the cover image
    img = Image.open(image_path)
    width, height = img.size
    pixel_values = list(img.getdata())
    
    # Convert message to binary
    binary_message = ''.join(format(ord(char), '08b') for char in message)
    binary_index = 0
    
    # Embed binary message into LSBs of pixel values
    for i in range(len(pixel_values)):
        pixel = list(pixel_values[i])
        for j in range(3):  # Iterate over RGB channels
            if binary_index < len(binary_message):
                pixel[j] &= ~1  # Clear the LSB
                pixel[j] |= int(binary_message[binary_index])  # Embed next bit
                binary_index += 1
        pixel_values[i] = tuple(pixel)
    
    # Create a new image with modified pixel values
    modified_img = Image.new('RGB', (width, height))
    modified_img.putdata(pixel_values)
    modified_img.save('modified_image.png')
    print("Message encoded successfully.")

def decode_message(image_path):
    img = Image.open(image_path)
    pixel_values = list(img.getdata())
    
    binary_message = ''
    for pixel in pixel_values:
        for value in pixel:
            binary_message += str(value & 1)  # Extract LSB
    
    # Convert binary message to ASCII characters
    message = ''.join(chr(int(binary_message[i:i+8], 2)) for i in range(0, len(binary_message), 8))
    return message

# Example usage
cover_image_path = 'two.png'
secret_message = "Hello, this is a hidden message!"

# Encode message into cover image
encode_message(cover_image_path, secret_message)

# Decode message from modified image
decoded_message = decode_message('modified_image.png')
print("Decoded message:", decoded_message)
