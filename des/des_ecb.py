from struct import unpack_from, pack, unpack, pack_into
from typing import List

from des.des_block import encrypt_block_i64

ENCRYPTION_PADDING = [bytes()] + [bytes([i] * i) for i in range(7, 0, -1)] + [bytes([8] * 8)]

PACKING_FORMAT = '!Q'


def encrypt_ecb(blocks: bytes, derived_keys: List[int], decryption: bool, padding=True):
    input_size = len(blocks)

    if decryption:
        derived_keys = list(reversed(derived_keys))
        last_block = unpack_from(PACKING_FORMAT, blocks, -8)[0]
        last_block = encrypt_block_i64(last_block, derived_keys)
        last_block = pack(PACKING_FORMAT, last_block)
        if padding:
            padding_size = last_block[-1]
            last_block = last_block[:-padding_size]
        trim_size = 8
    else:
        last_block_size = input_size % 8
        last_block = b''.join([blocks[-(last_block_size or 8):], ENCRYPTION_PADDING[last_block_size]])
        last_block = unpack(PACKING_FORMAT, last_block)[0]
        last_block = encrypt_block_i64(last_block, derived_keys)
        last_block = pack(PACKING_FORMAT, last_block)
        if padding:
            if last_block_size == 0:
                padding = unpack(PACKING_FORMAT, ENCRYPTION_PADDING[-1])[0]
                padding = encrypt_block_i64(padding, derived_keys)
                padding = pack(PACKING_FORMAT, padding)
                last_block = b''.join([last_block, padding])
                trim_size = 8
            else:
                trim_size = last_block_size
        else:
            if last_block_size != 0:
                raise ValueError('Count of bytes should be exactly multiply of 8 with automatic padding disabled.')
            trim_size = 8

    last_block_size = len(last_block)
    result = bytearray(input_size - trim_size + last_block_size)
    if last_block_size != 0:
        result[-last_block_size:] = last_block

    for i in range(0, input_size - 8, 8):
        block = unpack_from(PACKING_FORMAT, blocks, i)[0]
        block = encrypt_block_i64(block, derived_keys)
        pack_into(PACKING_FORMAT, result, i, block)

    return result
