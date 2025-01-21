from multiprocessing import cpu_count, Process
from datetime import datetime
from os import urandom
import time
import ctypes
from binascii import hexlify
from hashlib import sha256 as _sha256

alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
ice = ctypes.CDLL(r"/home/ubuntu/rbf/ice_secp256k1.so")
ice.init_secp256_lib()
res_main = (b'\x00') * 20
ice.privatekey_to_h160.argtypes = [ctypes.c_int, ctypes.c_bool, ctypes.c_char_p, ctypes.c_char_p]
init_bytes = (b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00')

wallet = b's\x947\xbb=\xd6\xd1\x98>fb\x9c_\x08\xc7\x0eRv\x93q'

def b58encode(bytestr):
    encoded = []
    num = int.from_bytes(bytestr, 'big')
    while num > 0:
        num, rem = divmod(num, 58)
        encoded.append(alphabet[rem])
    encoded = ''.join(encoded[::-1])
    pad = 0
    for byte in bytestr:
        if byte == 0:
            pad += 1
        else:
            break
    return '1' * pad + encoded

def b58encode_check(bytestr):
    return b58encode(bytestr + _sha256(_sha256(bytestr).digest()).digest()[:4])

def main():
    print("O jogo começou. Good Lucky :)")
    count = 0
    keys = 0
    start_time = time.time()
    seed = init_bytes
    while True:
        private = seed + urandom(7)
        key = hexlify(private)
        ice.privatekey_to_h160(0, True, key, res_main)
        count += 1
        keys += 1
        if res_main == wallet:
            wif = b58encode_check(b'\x80' + private + b'\x01')
            found_info = f'Found: p2pkh:{wif} - {private.hex()} - {datetime.now().strftime("%d/%m/%Y %H:%M:%S")}'
            print(found_info)
            with open((r"/home/ubuntu/rbf/found.txt"), 'a') as result:
                result.write(found_info + '\n')
                print("O jogo terminou :)")
                exit()
        if count >= 100000:
            elapsed_time = time.time() - start_time
            print(f'Chaves por segundo: {count/elapsed_time:,.2f} - {private.hex()[47:]} - {res_main.hex()} - {datetime.now().strftime("%d/%m/%Y %H:%M:%S")}')
            count = 0
            start_time = time.time()
        if keys >= 130000:
            keys = 0
            seed = int.from_bytes(seed, 'big')
            seed += 1
            if seed > 2047:
                seed = 1024
                seed = seed.to_bytes(25, 'big')
            else:
                seed = seed.to_bytes(25, 'big')

if __name__ == '__main__':
    num_processes = cpu_count()
    processes = [Process(target=main,) for _ in range(num_processes)]

    for p in processes:
        p.start()

    for p in processes:
        p.join()
