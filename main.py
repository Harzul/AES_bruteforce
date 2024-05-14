from binascii import unhexlify
from itertools import permutations, islice
from math import ceil, perm
from multiprocessing import Pool
from timeit import default_timer as timer
from fastpbkdf2 import pbkdf2_hmac

from aes import decrypt

class Brute:
    __slots__ = ('iterations', 'text_size', 'cipher_text')

    def __init__(self, iterations: int, size: int, text: str) -> None:
        self.iterations = iterations
        self.text_size = size
        self.cipher_text = unhexlify(text)

    def worker(self, i: str) -> None:
        key = pbkdf2_hmac('sha1', i.encode('utf-8'), b'SALT', self.iterations, dklen=16)
        message = decrypt(key, self.cipher_text).decode('iso-8859-1').strip()

        if len(message) == self.text_size:
            print(len(message.strip()))
            print("|||||||||||||||||||||||||||||||||||||||||||||||||||||||")
            print(f'Len: {len(message)}\nOpen text: {message}\nKey: {i}')
            print("|||||||||||||||||||||||||||||||||||||||||||||||||||||||")
            with open('r.txt', 'w') as f:
                f.write(f'Len: {len(message)}\nOpen text: {message}\nKey: {i}')

    @staticmethod
    def __generate_all_sequences(characters: str, length: int):
        sequences = permutations(characters, length)
        return sequences

    # 20 потоков 1.4млн
    def Bruteforce(self, pass_len: int, block_size: int, charset: str) -> None:
        combos = self.__generate_all_sequences(charset, pass_len)
        with Pool(processes=20) as pool:
            for i in range(0, ceil((perm(len(charset), pass_len)) / block_size)):
                passwords = list(islice((''.join(x) for x in combos), block_size))
                print(f'Passwords generation done')
                print(passwords[-1])
                print(len(passwords))
                start = timer()
                pool.map(self.worker, passwords)
                print(timer() - start)
                del passwords


def main() -> None:
    bruter = Brute(0x000000a9, 0x00000017,
                   '8b4f4a770d1ce8c2b280056b84f4692a756c50fa8c0120e2562defd0677d0a11')
    bruter.Bruteforce(8, 50_000_000, 'dHloiegsb4659qw')


if __name__ == "__main__":
    main()
