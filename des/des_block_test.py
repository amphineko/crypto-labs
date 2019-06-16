from des.des_block import key_derive, encrypt_block_i64


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
    derived_keys = list(key_derive(key))
    print(f'Pre-configured encryption key:\t{hex(key)}')

    block = int('1145141919810AAA', 16)
    print(f'Source block:\t{hex(block)}')

    encrypted_result = encrypt_block_i64(block, derived_keys)
    print(f'Encryption result:\t{hex(encrypted_result)}')

    print(f'Reference result:\t{hex(get_reference_encryption(block, key))}')

    derived_keys = list(reversed(derived_keys))
    decrypted_result = encrypt_block_i64(encrypted_result, derived_keys)
    print(f'Decryption result:\t{hex(decrypted_result)}')


if __name__ == '__main__':
    test()
