from utils import *
import pandas as pd
import time
import Emularis
import math

print("=======================test for time cost========================")
Emularis_sign_time_list = []
Emularis_verify_time_list = []

Address_num = 5
for power in range (10):
    power_of_2 = power + 1
    PK_num = 2 ** power_of_2
    print(">>> PK_num %d" % PK_num)
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
        Emularis_sign = time.time()
        hh = Emularis.Sign("foo", fake_PK, my_sk, random_position)
        Emularis_sign_time = time.time() - Emularis_sign
        Emularis_sign_time_list.append(Emularis_sign_time)
        print("Emularis_sign_time is %f" % (Emularis_sign_time))

        Emularis_verify = time.time()
        Emularis.Verify("foo", fake_PK, hh)
        Emularis_verify_time = time.time() - Emularis_verify
        Emularis_verify_time_list.append(Emularis_verify_time)
        print("Emularis_verify_time is %f" % Emularis_verify_time)

    # writing to file
    with open("Emularis Time Cost Analysis.txt", "w") as text_file:
        for i in range (len(Emularis_sign_time_list)):
            text_file.write("%d,%f,%f\n" % (math.pow(2, i+1),  Emularis_sign_time_list[i], Emularis_verify_time_list[i]))

data = pd.read_csv('Emularis Time Cost Analysis.txt', names= ['Ring size', 'Emularis SIGN', 'Emularis VERIFY'])
print(data)

data.to_csv('Emularisdata.csv', index = 0)