# manually recovered pseudocode from flake binary

from Crypto.Cipher import ARC4
import os
import sys
import json
import base64


def main():
  read_config()
  next_turn()
  
  
def xor(data, key):
    data = bytearray(data)
    for i in range(len(data)):
        data[i] ^= key[i % len(key)]
    return data


def read_config():
    """XOR-encode d3m0_c0nf.txt with 0x22,0x11,0x91,0xff (I think Nuikta strips Python docstrings during compilation so no worries about this comment making its way into the wrong hands)"""
    conf_name = "d3m0_c0nf.txt"
    conf_path = os.path.join(os.path.dirname(sys.argv[0]), conf_name)
    if os.path.isfile(conf_path):
        try:
            with open(conf_path, "rb") as f:
                data = base64.b64decode(f.read())
            key = bytes([34, 17, 145, 255])
            decrypted_data = xor(data, key)
            result = json.loads(decrypted_data.decode("utf-8"))
            print("[!] configuration file found and decoded with key - using demo configuration")
            print(result, end="\n\n")
            
        except:
            print("[!] bad configuration file - using prod configuration")
    else:
        print("[!] could not find configuration file in directory - using prod configuration")


def next_turn():
	if check_collisions():
		if score >= 10000:
			if check_snake_length(snake, score):
				game_win()
			else:
				shame()
		game_over()


def game_win():
	get_flag()


def get_flag(
    enc_key=b'T\x00\xc6\x88g\xf9_nx}\x91]X\xb2^g[\xf40\x860\xe4D\x19\xea\x94\x136\x97m\xc9\xd8\xb9r?(\xe8\xea\r3\x92\x8e\xa9\x03\xef\xa8\x8e\x9d\xb7\x83',
    xk=bytes([27, 186, 140, 27])
):

	key = xor(enc_key, xk)
	enc_flag = b"\xbbh\xd5P\x88\xc3$\x1bM\xdc\xc2\x9d\x89\xaafGx\xa6\xdb\x82\x02\xc6V\xce\xbb\x95@\x7f'*`\xee\xc0i"
	flag = ARC4.new(key).decrypt(enc_flag)
	print(flag.decode())


#read_config()
get_flag()
