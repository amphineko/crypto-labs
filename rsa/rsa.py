import random


def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a


def ex_gcd(a, b):
    x, x1 = 0, 1
    y, y1 = 1, 0

    while b != 0:
        q = a // b
        a, b = b, a - q * b
        x, x1 = x1 - q * x, x
        y, y1 = y1 - q * y, y

    return x1


def generate_key_pair(p, q):
    n = p * q
    phi = (p - 1) * (q - 1)

    e = random.randrange(1, phi)  # public key

    g = gcd(e, phi)
    while g != 1:
        e = random.randrange(1, phi)
        g = gcd(e, phi)

    d = ex_gcd(e, phi)  # private key
    if d < 0:
        d += phi

    return (e, n), (d, n)


def encrypt(key, message):
    key, n = key
    return [(char ** key) % n for char in message]


def main():
    p, q = 7, 19
    print(f'Prime p, q = {p}, {q}')
    e, d = generate_key_pair(p, q)
    print(f"Public-key, Private-key = {e, d}")

    message = 'nekomimi'
    print(f'Message:\t{message}')
    encoded = message.encode('utf-8')
    print(f'Encoded:\t{"".join([hex(i)[-2:] for i in encoded])}')
    encrypted = bytes(encrypt(e, encoded))
    print(f'Encrypted:\t{"".join([hex(i)[-2:] for i in encrypted])}')
    decrypted = bytes(encrypt(d, encrypted))
    print(f'Decrypted:\t{"".join([hex(i)[-2:] for i in decrypted])}')
    decoded = decrypted.decode('utf-8')
    print(f'Decoded:\t{decoded}')


if __name__ == '__main__':
    main()
