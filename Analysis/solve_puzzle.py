import numpy as np
from PIL import Image

def load_image_data(image_path):
    """Loads the image and returns a numpy array."""
    img = Image.open(image_path)
    data = np.array(img).astype(float) / 255.0
    # Take only one channel
    data = data[:, :, 0]
    # Delete the non-rectangle data
    data[780:950, 1:140] = 0
    data[780:950, 770:950] = 0
    data[890:950, 1:950] = 0
    return data

def get_rectangle_centers():
    """Returns the hardcoded centers of the 64 rectangles."""
    return np.array([
        [125, 215], [125, 290], [125, 370], [125, 445], [125, 510], [125, 600], [123, 670], [125, 730],
        [223, 240], [223, 278], [223, 327], [223, 400], [223, 470], [223, 525], [223, 578], [223, 670],
        [322, 247], [322, 335], [322, 416], [322, 489], [322, 543], [322, 590], [322, 650], [322, 704],
        [420, 192], [420, 273], [420, 342], [420, 403], [420, 477], [420, 562], [420, 640], [420, 738],
        [522, 245], [522, 299], [522, 362], [522, 417], [522, 478], [522, 564], [522, 632], [522, 691],
        [623, 274], [623, 324], [623, 386], [623, 454], [623, 507], [623, 547], [623, 588], [623, 650],
        [720, 230], [720, 323], [720, 397], [720, 490], [722, 570], [722, 602], [722, 642], [722, 718],
        [822, 243], [822, 320], [822, 380], [822, 450], [822, 523], [822, 591], [822, 648], [822, 703]
    ])

def get_rectangle_coords(data, centers):
    """Calculates the coordinates of the inner and outer rectangles."""
    X = np.zeros((64, 4), dtype=int)
    Y = np.zeros((64, 4), dtype=int)

    for i in range(64):
        center_y, center_x = centers[i]

        # Find x-coordinates
        row = data[center_y, :]
        xi_1 = np.where((row == 1) & (np.arange(data.shape[1]) < center_x))[0][-1]
        xi_2 = np.where((row == 1) & (np.arange(data.shape[1]) >= center_x))[0][0]
        xo_1 = np.where((row == 0) & (np.arange(data.shape[1]) <= xi_1))[0][-1] + 1
        xo_2 = np.where((row == 0) & (np.arange(data.shape[1]) >= xi_2))[0][0] - 1
        X[i, :] = [xo_1, xi_1, xi_2, xo_2]

        # Find y-coordinates
        col = data[:, center_x]
        yi_1 = np.where((col == 1) & (np.arange(data.shape[0]) < center_y))[0][-1]
        yi_2 = np.where((col == 1) & (np.arange(data.shape[0]) >= center_y))[0][0]
        yo_1 = np.where((col == 0) & (np.arange(data.shape[0]) <= yi_1))[0][-1] + 1
        yo_2 = np.where((col == 0) & (np.arange(data.shape[0]) >= yi_2))[0][0] - 1
        Y[i, :] = [yo_1, yi_1, yi_2, yo_2]

    return X, Y

def calculate_areas(X, Y):
    """Calculates the areas of the inner and outer rectangles."""
    A = np.zeros((64, 2), dtype=int)
    for i in range(64):
        xo_1, xi_1, xi_2, xo_2 = X[i, :]
        yo_1, yi_1, yi_2, yo_2 = Y[i, :]
        A_o = (abs(xo_1 - xo_2) + 1) * (abs(yo_1 - yo_2) + 1)
        A_i = (abs(xi_1 - xi_2) - 2 + 1) * (abs(yi_1 - yi_2) - 2 + 1)
        A[i, :] = [A_o, A_i]
    return A

import codecs
import hashlib
import base58
import ecdsa

def pk_to_hash_unc_p2pkh(priv_key):
    private_key_bytes = codecs.decode(priv_key, 'hex')
    key = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1).verifying_key
    key_bytes = key.to_string()
    key_hex = codecs.encode(key_bytes, 'hex')
    bitcoin_byte = b'04'
    public_key = bitcoin_byte + key_hex
    public_key_bytes = codecs.decode(public_key, 'hex')
    sha256_bpk = hashlib.sha256(public_key_bytes)
    sha256_bpk_digest = sha256_bpk.digest()
    ripemd160_bpk = hashlib.new('ripemd160')
    ripemd160_bpk.update(sha256_bpk_digest)
    ripemd160_bpk_digest = ripemd160_bpk.digest()
    ripemd160_bpk_hex = codecs.encode(ripemd160_bpk_digest, 'hex')
    return ripemd160_bpk_hex

def pk_to_hash_c_p2pkh(priv_key):
    private_key_bytes = codecs.decode(priv_key, 'hex')
    key = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1).verifying_key
    key_bytes = key.to_string()
    if key_bytes[-1] & 1:
        bitcoin_byte = b'03'
    else:
        bitcoin_byte = b'02'
    key_bytes = key_bytes[0:32]
    key_hex = codecs.encode(key_bytes, 'hex')
    public_key = bitcoin_byte + key_hex
    public_key_bytes = codecs.decode(public_key, 'hex')
    sha256_bpk = hashlib.sha256(public_key_bytes)
    sha256_bpk_digest = sha256_bpk.digest()
    ripemd160_bpk = hashlib.new('ripemd160')
    ripemd160_bpk.update(sha256_bpk_digest)
    ripemd160_bpk_digest = ripemd160_bpk.digest()
    ripemd160_bpk_hex = codecs.encode(ripemd160_bpk_digest, 'hex')
    return ripemd160_bpk_hex

def rp160hash_to_p2pkhAddress(rp160hash):
    network_byte = b'00'
    network_bitcoin_public_key = network_byte + rp160hash
    network_bitcoin_public_key_bytes = codecs.decode(network_bitcoin_public_key, 'hex')
    sha256_nbpk = hashlib.sha256(network_bitcoin_public_key_bytes)
    sha256_nbpk_digest = sha256_nbpk.digest()
    sha256_2_nbpk = hashlib.sha256(sha256_nbpk_digest)
    sha256_2_nbpk_digest = sha256_2_nbpk.digest()
    sha256_2_hex = codecs.encode(sha256_2_nbpk_digest, 'hex')
    checksum = sha256_2_hex[:8]
    address_hex = (network_bitcoin_public_key + checksum).decode('utf-8')
    address = base58.b58encode(bytes(bytearray.fromhex(address_hex))).decode('utf-8')
    return address

def get_pairing_indices():
    """Returns the four pairing strategies."""
    idx = []
    # Strategy 1
    idx.append(np.array([((np.arange(32)) * 2 + 1), ((np.arange(32)) * 2 + 2)]).T - 1)
    # Strategy 2
    idx.append(np.array([np.concatenate([np.arange(1, 9), np.arange(17, 25), np.arange(33, 41), np.arange(49, 57)]),
                           np.concatenate([np.arange(9, 17), np.arange(25, 33), np.arange(41, 49), np.arange(57, 65)])]).T - 1)
    # Strategy 3
    idx.append(np.arange(64).reshape(8, 8).T.reshape(32, 2))
    # Strategy 4
    idx.append(np.array([
        [1, 9, 17, 25, 33, 41, 49, 57, 3, 11, 19, 27, 35, 43, 51, 59, 5, 13, 21, 29, 37, 45, 53, 61, 7, 15, 23, 31, 39, 47, 55, 63],
        [2, 10, 18, 26, 34, 42, 50, 58, 4, 12, 20, 28, 36, 44, 52, 60, 6, 14, 22, 30, 38, 46, 54, 62, 8, 16, 24, 32, 40, 48, 56, 64]
    ]).T - 1)
    return idx

def generate_and_check_keys(A, pairing_indices, line_handling):
    """Generates and checks private keys."""
    target_address = '1cryptoGeCRiTzVgxBQcKFFjSVydN1GW7'
    all_keys = []

    byte_values_matrix = np.zeros((32, 12))
    idea_counter = 0
    for i, idx in enumerate(pairing_indices):
        for area_type in range(3):  # 0: inner, 1: outer, 2: shell
            byte_values = np.zeros(32)
            for j in range(32):
                idx_1, idx_2 = idx[j]
                if area_type == 0: # inner
                    byte_values[j] = A[idx_1, 1] + A[idx_2, 1]
                elif area_type == 1: # outer
                    byte_values[j] = A[idx_1, 0] + A[idx_2, 0]
                else: # shell
                    byte_values[j] = (A[idx_1, 0] - A[idx_1, 1]) + (A[idx_2, 0] - A[idx_2, 1])
            byte_values_matrix[:, idea_counter] = byte_values
            idea_counter += 1

    # Modulo option
    for i in range(12):
        key_bytes = byte_values_matrix[:, i] % 256
        all_keys.append("".join([f"{int(b):02x}" for b in key_bytes]))
    # Dummy normalization
    for i in range(12):
        byte_values = byte_values_matrix[:, i]
        key_bytes = np.floor((byte_values / np.max(byte_values)) * 255)
        all_keys.append("".join([f"{int(b):02x}" for b in key_bytes]))
    # Better normalization
    for i in range(12):
        byte_values = byte_values_matrix[:, i]
        key_bytes = np.floor(((byte_values - np.min(byte_values)) / (np.max(byte_values) - np.min(byte_values))) * 255)
        all_keys.append("".join([f"{int(b):02x}" for b in key_bytes]))

    # Hint transformation
    for i in range(12):
        byte_values = byte_values_matrix[:, i]
        x = byte_values
        transformed_bytes = -1 * x + 64 / (x + 1e-9)
        key_bytes = transformed_bytes
        all_keys.append("".join([f"{(int(b) & 0xff):02x}" for b in key_bytes]))

        key_bytes = np.floor((transformed_bytes / np.max(transformed_bytes)) * 255)
        all_keys.append("".join([f"{(int(b) & 0xff):02x}" for b in key_bytes]))

        key_bytes = np.floor(((transformed_bytes - np.min(transformed_bytes)) / (np.max(transformed_bytes) - np.min(transformed_bytes))) * 255)
        all_keys.append("".join([f"{(int(b) & 0xff):02x}" for b in key_bytes]))


    with open(f"keys_{line_handling}.txt", "w") as f:
        for key in all_keys:
            f.write(key.upper() + "\n")

    for pk in all_keys:
        address_c = rp160hash_to_p2pkhAddress(pk_to_hash_c_p2pkh(pk))
        if address_c == target_address:
            print(f"Found key: {pk} | compressed")
            return pk

        address_unc = rp160hash_to_p2pkhAddress(pk_to_hash_unc_p2pkh(pk))
        if address_unc == target_address:
            print(f"Found key: {pk} | uncompressed")
            return pk
    return None


if __name__ == '__main__':
    image_data = load_image_data('crypto5fix.png')
    rect_centers = get_rectangle_centers()
    X, Y = get_rectangle_coords(image_data, rect_centers)
    A = calculate_areas(X, Y)

    pairing_indices = get_pairing_indices()

    for line_handling in ['noLine', 'minus', 'plus', 'multiply']:
        A_modified = A.copy()
        if line_handling == 'minus':
            A_modified[39, 0] -= 17
            A_modified[52, 0] -= 6
        elif line_handling == 'plus':
            A_modified[39, 0] += 17
            A_modified[52, 0] += 6
        elif line_handling == 'multiply':
            A_modified[39, 0] *= 17
            A_modified[52, 0] *= 6

        print(f"Checking keys for line handling: {line_handling}")
        found_key = generate_and_check_keys(A_modified, pairing_indices, line_handling)
        if found_key:
            print(f"SUCCESS! Found key: {found_key}")
            break
