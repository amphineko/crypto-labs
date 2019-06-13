from typing import List

from des.des_params import EXPANSION, SUBSTITUTION_BOX, PERMUTATION, ROTATES, INITIAL_PERMUTATION, INVERSE_PERMUTATION, \
    PERMUTED_CHOICE1, PERMUTED_CHOICE2


def permute(data: int, size: int, matrix: List[int]):
    # input: network-endian key
    ret = 0
    for result_index, source_index in enumerate(matrix):
        if data & 1 << (size - 1 - source_index):  # detect if bit is positive
            ret |= 1 << (len(matrix) - 1 - result_index)  # flip result bit
    return ret


def rotate_left(i28: int, k: int):
    return i28 << k & 0x0fffffff | i28 >> 28 - k


def derive_keys(key: int):
    # Step 1: Create 16 sub-keys, each of which is 48-bits long.
    key = permute(key, 64, PERMUTED_CHOICE1)
    k_left, k_right = key >> 28, key & 0x0fffffff
    for rotate in ROTATES:
        k_left, k_right = rotate_left(k_left, rotate), rotate_left(k_right, rotate)
        yield permute(k_left << 28 | k_right, 56, PERMUTED_CHOICE2)


def f(block: int, key: int):
    block = permute(block, 32, EXPANSION) ^ key  # apply E bit-selection table, or E(R[n-1])
    ret = 0
    for i, box in enumerate(SUBSTITUTION_BOX):  # apply S-Box
        i6 = block >> 42 - i * 6 & 0x3f
        ret = ret << 4 | box[i6 & 0x20 | (i6 & 0x01) << 4 | (i6 & 0x1e) >> 1]
    return permute(ret, 32, PERMUTATION)


def encrypt_block(block_i64: int, derived_keys, decryption=False):
    # apply initial permutation
    block_ip = permute(block_i64, 64, INITIAL_PERMUTATION)
    # create l[0], r[0]
    l, r = block_ip >> 32, block_ip & 0xffffffff

    if decryption:
        derived_keys = list(reversed(derived_keys))

    # 16 iterations
    assert len(derived_keys) == 16
    for key in derived_keys:
        # l[n] = r[n-1], r[i] = l[n-1] xor f(r[n-1], derived_keys[n])
        l, r = r, l ^ f(r, key)

    return permute(r << 32 | l, 64, INVERSE_PERMUTATION)


def get_reference_encryption(block: int, key: int):
    from pyDes import des
    from struct import pack, unpack

    block = pack('!Q', block)
    key = pack('!Q', key)

    des = des(key=key)
    return unpack('!Q', des.encrypt(block))[0]


def test():
    print('Single block DES encryption test')

    key = int('1145141919810AAA', 16)
    derived_keys = list(derive_keys(key))
    print(f'Pre-configured encryption key:\t{hex(key)}')

    block = int('1145141919810AAA', 16)
    print(f'Source block:\t{hex(block)}')

    encrypted_result = encrypt_block(block, derived_keys, False)
    print(f'Encryption result:\t{hex(encrypted_result)}')

    print(f'Reference result:\t{hex(get_reference_encryption(block, key))}')

    decrypted_result = encrypt_block(encrypted_result, derived_keys, True)
    print(f'Decryption result:\t{hex(decrypted_result)}')


if __name__ == '__main__':
    test()
