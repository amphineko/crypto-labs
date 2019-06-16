from typing import List

from des.des_params import EXPANSION, SUBSTITUTION_BOX, PERMUTATION, ROTATES, INITIAL_PERMUTATION, INVERSE_PERMUTATION, \
    PERMUTED_CHOICE1, PERMUTED_CHOICE2


def apply(data: int, size: int, matrix: List[int]):
    ret = 0
    for result_index, source_index in enumerate(matrix):
        if data & 1 << (size - 1 - source_index):  # detect if bit is positive
            ret |= 1 << (len(matrix) - 1 - result_index)  # flip result bit
    return ret


def key_rotate_left(i28: int, k: int):
    return i28 << k & 0x0fffffff | i28 >> 28 - k


def key_derive(key: int):
    # Step 1: Create 16 sub-keys, each of which is 48-bits long.
    key = apply(key, 64, PERMUTED_CHOICE1)
    k_left, k_right = key >> 28, key & 0x0fffffff
    for rotate in ROTATES:
        k_left, k_right = key_rotate_left(k_left, rotate), key_rotate_left(k_right, rotate)
        yield apply(k_left << 28 | k_right, 56, PERMUTED_CHOICE2)


def f(block: int, key: int):
    block = apply(block, 32, EXPANSION) ^ key  # apply E bit-selection table, or E(R[n-1])
    ret = 0
    for i, box in enumerate(SUBSTITUTION_BOX):  # apply S-Box
        i6 = block >> 42 - i * 6 & 0x3f
        ret = ret << 4 | box[i6 & 0x20 | (i6 & 0x01) << 4 | (i6 & 0x1e) >> 1]
    return apply(ret, 32, PERMUTATION)


def encrypt_block_i64(block_i64: int, derived_keys: List[int]):
    # apply initial permutation
    block_ip = apply(block_i64, 64, INITIAL_PERMUTATION)
    # create l[0], r[0]
    l, r = block_ip >> 32, block_ip & 0xffffffff

    # 16 iterations
    assert len(derived_keys) == 16
    for key in derived_keys:
        # l[n] = r[n-1], r[i] = l[n-1] xor f(r[n-1], derived_keys[n])
        l, r = r, l ^ f(r, key)

    return apply(r << 32 | l, 64, INVERSE_PERMUTATION)
