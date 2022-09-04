from utils import *
import Emularis

print("======================test for correctness=======================")
Address_num = 5
for power in range (8):
    power_of_2 = power + 1
    PK_num = 2 ** power_of_2
    time_trail = 1
    fake_PK = matrix_gen(PK_num, Address_num)
    ssk = [None for _ in range(Address_num)]
    ppk = [None for _ in range(Address_num)]
    my_sk = [None for _ in range(Address_num)]
    for i in range (0, PK_num):
        for j in range (0, Address_num):
            foo, fake_PK[i][j] = KeyGen()
    for j in range (0, Address_num):
        ssk[j], ppk[j] = KeyGen()
    
    for ii in range (time_trail):
        random_position = secrets.randbelow(PK_num)
        my_sk, fake_PK[random_position] = ssk, ppk
        hh = Emularis.Sign("foo", fake_PK, my_sk, random_position)
        if Emularis.Verify("foo", fake_PK, hh) != 1:
            print ("failed")
print("Emularis success!")
