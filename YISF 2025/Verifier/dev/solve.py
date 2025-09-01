from pwn import *

hash_table = {
    b"312a" : b"3355b58b97617985ad032226043d3008c5dc915288326e0074654ba344f5b471",
    b"91ac" : b"d2c2198d191d3c2f14bba11fe2bb4396bd1dfb7d3df32b70e472d15a72eed13f",
    b"41ca" : b"74515ecf40255d006ecaca61026235e0694b9916be6fbdd62c4581d58664b5b4",
    b"5132" : b"a77b3237cb73acfb0e31f93694398f8e7dc158edb14552cbede81d9bf3839e86"
}

SUM = sum([u32(v) for v in hash_table.keys()]) & 0xffffffff
name = xor(b"\xac\xf5\x1c>\xe7\xf4\x1bm", p32(SUM))
serial = b"-".join(hash_table.keys())

print(name, serial)