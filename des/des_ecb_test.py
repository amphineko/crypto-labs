from struct import pack

import pyDes

from des.des_block import key_derive
from des.des_ecb import encrypt_ecb


def get_reference_encryption(data: bytes, key: bytes):
    des = pyDes.des(key, pyDes.ECB, padmode=pyDes.PAD_PKCS5)
    return des.encrypt(data)


if __name__ == '__main__':
    key = input('Encryption key:')
    key = int(key, 16)
    print(f'Pre-configured encryption key:\t{hex(key)}')
    derived_keys = list(key_derive(key))

    data = input('Source text:')
    print(f'Source text:\t{data}')
    data = data.encode('utf-8')
    print(f'Encoded UTF-8:\t{"".join([hex(i)[-2:] for i in data])}')

    encrypted = encrypt_ecb(data, derived_keys, False, padding=True)
    print(f'Encryption:\t\t{"".join([hex(i)[-2:] for i in encrypted])}')

    ref = get_reference_encryption(data, pack('!Q', key))
    print(f'Reference:\t\t{"".join([hex(i)[-2:] for i in ref])}')

    decrypted = encrypt_ecb(encrypted, derived_keys, True, padding=True)
    print(f'Decryption:\t\t{"".join([hex(i)[-2:] for i in decrypted])}')

    print(f'Decoded UTF-8:\t{decrypted.decode("utf-8")}')
