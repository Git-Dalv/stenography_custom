input_pick = r"C:\input_pick.png"
# r"Str" - Used to ignore special characters

def load_input(file_path):
    with open(file_path, "rb") as file:
        data = file.read()
    return data
# Open the file and return its byte code

def find_idat(data):
    start_index = data.find(b"IDAT")  # b"" is used to work with bytes
    if start_index == -1:
        raise ValueError("Section not found")
    return start_index
# Method to find the beginning of the IDAT section => the place where we apply steganography by modifying the last bit.

def extarct_pixel_data(data, idat_index):  # Retrieve pixel data after IDAT
    # Length of chunk data (4 bytes before IDAT)
    chunk_length = int.from_bytes(data[idat_index - 4:idat_index], 'big')
    # Start of chunk data (after the IDAT header)
    pixel_data_start = idat_index + 4  # Skip "IDAT"
    # End of chunk data (excluding CRC)
    pixel_data_end = pixel_data_start + chunk_length
    # Extract data
    pixel_data = data[pixel_data_start:pixel_data_end]
    return pixel_data

def find_crc_for_IDAT(data):
    offset = 8  # Skip the 8-byte PNG signature
    while offset < len(data):
        # Length of chunk data
        length = int.from_bytes(data[offset:offset+4], 'big')
        # Type of chunk
        chunk_type = data[offset+4:offset+8].decode('ascii')
        # CRC position (last 4 bytes of the chunk)
        crc_offset = offset + 8 + length
        crc = int.from_bytes(data[crc_offset:crc_offset+4], 'big')

        print(f"Chunk: {chunk_type}, CRC: {crc:08X}, length: {length}")

        # Move to the next chunk
        offset = crc_offset + 4
        if chunk_type == "IDAT":
            return crc

def find_data_for_IDAT(data):
    offset = 8  # Skip the 8-byte PNG signature
    while offset < len(data):
        # Length of chunk data
        length = int.from_bytes(data[offset:offset+4], 'big')
        # Type of chunk
        chunk_type = data[offset+4:offset+8].decode('ascii')
        # CRC position (last 4 bytes of the chunk)
        crc_offset = offset + 8 + length
        crc = int.from_bytes(data[crc_offset:crc_offset+4], 'big')
        if chunk_type == "IDAT":
            return data[offset+8:length]
        # Move to the next chunk
        return data[offset + 8:offset + 8 + length]

def calculate_crc(data):
    POLYNOMIAL = 0xEDB88320  # Polynomial for PNG CRC-32
    """
    Based on the analysis of all possible polynomials, this one became the standard (IEEE 802.3).
    In short, it was the most efficient in detecting errors, such as:

    * Inversion of 1 bit
    * Inversion of different or identical bits
    * "Short packet" errors: Errors up to 32 bits long
    * Errors with an odd number of bits

    There are 2^32 possible 32-bit polynomials, but due to the most significant bit,
    there are only 2^31 = 2,147,483,648 options.
    """
    # Initialize CRC
    crc = 0xFFFFFFFF

    for byte in data:
        crc ^= byte  # XOR the current CRC with the byte
        for _ in range(8):  # Iterate through each bit
            if crc & 1:  # If the least significant bit is set
                crc = (crc >> 1) ^ POLYNOMIAL  # Shift right by 1
            else:
                crc >>= 1

    # Invert the final CRC
    return crc ^ 0xFFFFFFFF

def text_to_binary(text):
    binary_data = "".join(format(ord(char), "08b") for char in text)
    # Add to an empty string through the loop: first in ASCII, then convert to 8-bit binary representation.
    # format(ord(char), '08b') and the loop itself.
    binary_data += "1111111111111110"  # Delimiter
    return binary_data

def embed_text_in_idat(idat_data, binary_text):
    idat_data = bytearray(idat_data)  # bytes -> bytearray because bytes is immutable, unlike bytearray
    data_index = 0  # Index of the current bit

    for i in range(len(idat_data)):  # Here we perform steganography on the IDAT data
        if data_index < len(binary_text):
            idat_data[i] = (idat_data[i] & ~1) | int(binary_text[data_index])
            # This involves slightly complex logic using ~ (NOT), | (OR), and & (AND) operators.
            # The essence is replacing the least significant bit, which enables steganography.
            data_index += 1
        else:
            break
    return bytes(idat_data)

def save_modified_png(save_path, original_data, idat_index, modified_idat_data, new_crc):
    # Restore the PNG with modified data
    new_crc = calculate_crc(modified_idat_data)
    modified_data = original_data[:idat_index+4] + modified_idat_data + new_crc.to_bytes(4, 'big')
    modified_data += original_data[idat_index + 4 + len(modified_idat_data) + 4:]
    with open(save_path, "wb") as file:
        file.write(modified_data)
    print(f"Modified image saved to {save_path}")

hidden_text = "hi"
binary_text = text_to_binary(hidden_text)

image_path = input_pick
image_data = load_input(image_path)
idat_index = find_idat(image_data)

pixel_data = extarct_pixel_data(image_data, idat_index)
modified_idat_data = embed_text_in_idat(pixel_data, binary_text)

data_idat = find_data_for_IDAT(image_data)
crc_idat = find_crc_for_IDAT(image_data)
new_crc = calculate_crc(modified_idat_data)

save_path = "output.png"
save_modified_png(save_path, image_data, idat_index, modified_idat_data, new_crc)

print("New data: ", modified_idat_data)
print(f"CRC_IDAT: {crc_idat:08X}")
print(f"DATA_IDAT: {data_idat}")

output_data = load_input("output.png")

print(f"First 50 bytes of code: {image_data[:150]}")
print(f"\nIDAT starts at: {idat_index}")
print(f"\nPixels after IDAT (first 50): {pixel_data}")
print(f"Binary representation of text {hidden_text} -> {binary_text}")
print(f" Byte code of input: {image_data[72:]}")
print(f"Byte code of output: {output_data[72:]}")


def chek_it(original, modif, binary_text):
    print(binary_text, len(binary_text))
    for a,i in enumerate(original):
        if original[a] != modif[a]:
            res = binary_text[a]
            print(f"Different bits      {a}: original: {format(original[a], "08b")} || modif:{format(modif[a],"08b")}=>{res}")
        #Where is my bits???
        #Got it, not every bit changes, sometimes there are matches


def compare_idat_bytes(original, modified):

    differences = []

    for i in range(len(original)):
        if original[i] != modified[i]:
            if (original[i] & ~1) != (modified[i] & ~1):
                differences.append((i, original[i], modified[i], "Not just LSB"))
            else:
                differences.append((i, original[i], modified[i], "Only LSB"))

    return differences

print(compare_idat_bytes(pixel_data, modified_idat_data))
chek_it(pixel_data, modified_idat_data,binary_text)
