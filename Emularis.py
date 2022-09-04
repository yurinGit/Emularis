from utils import *
from gmpy2 import invert

def Sign(M, PK, sk, index):
    n = len(PK)
    m = len(PK[0])

    H = matrix_gen(n, m)
    for i in range(n):
        for j in range(m):
            H[i][j] = HashToPoint(PK[i][j])
    IK_vector = [Image_key(sk[j], PK[index][j]) for j in range(m)]

    r = [secrets.randbelow(p) for _ in range(m)]
    a = [secrets.randbelow(p) for _ in range(m)]
    c = [None for _ in range(n)]

    L = [None for _ in range(m)]
    R = [None for _ in range(m)]

    s = [None for _ in range(m)]
    z = [None for _ in range(m)]

    for j in range(m):
        L[j] = r[j] * g
        R[j] = a[j] * IK_vector[j]
    
    summation_except_index = 0
    for i in range (n):
        if i == index:
            continue
        temp_c = secrets.randbelow(p)
        c[i] = temp_c
        for j in range(m):
            L[j] = L[j] + (PK[i][j] * temp_c)
            R[j] = R[j] + (H[i][j] * temp_c)
        summation_except_index += temp_c

    my_string = M + catMultipleAddress(L, m) + catMultipleAddress(R, m)
    c_number = int(sha256(my_string.encode()).hexdigest(), 16) % p
    c[index] = (c_number - summation_except_index) % p

    for j in range(m):
        s[j] = (r[j] - c[index] * sk[j]) % p
        z[j] = (a[j] - c[index] * int(invert(sk[j], p))) % p

    b = [None for _ in range(m)]
    my_string = M + pt_to_string(L[0]) + pt_to_string(R[0]) + str(0)
    b[0] = int(sha256(my_string.encode()).hexdigest(), 16) % p
    L_ = b[0] * L[0]
    R_ = b[0] * R[0]
    P = L_ - b[0] * s[0] * g + R_ - b[0] * z[0] * IK_vector[0]

    for j in range(1, m):
        my_string = M + pt_to_string(L[j]) + pt_to_string(R[j]) + str(j)
        b[j] = int(sha256(my_string.encode()).hexdigest(), 16) % p
        L_ = b[j] * L[j]
        R_ = b[j] * R[j]
        P = P + L_ - b[j] * s[j] * g + R_ - b[j] * z[j] * IK_vector[j]

    ph_list = []
    for i in range(n):
        temp = b[0] * (PK[i][0] + H[i][0])
        for j in range(1, m):
            temp += b[j] * (PK[i][j] + H[i][j])
        ph_list.append(temp)

    pi = NISA_Proof(ph_list, P, c_number, c)
    return c_number, s, z, L, R, pi, IK_vector

def Verify(M, PK, sigma):
    c_number = sigma[0]
    s = sigma[1]
    z = sigma[2]
    L = sigma[3]
    R = sigma[4]
    pi = sigma[5]
    IK_vector = sigma[6]

    n = len(PK)
    m = len(PK[0])

    H = matrix_gen(n, m)
    for i in range(n):
        for j in range(m):
            H[i][j] = HashToPoint(PK[i][j])

    b = [None for _ in range(m)]
    my_string = M + pt_to_string(L[0]) + pt_to_string(R[0]) + str(0)
    b[0] = int(sha256(my_string.encode()).hexdigest(), 16) % p
    L_ = b[0] * L[0]
    R_ = b[0] * R[0]
    P = L_ - b[0] * s[0] * g + R_ - b[0] * z[0] * IK_vector[0]

    
    for j in range(1, m):
        my_string = M + pt_to_string(L[j]) + pt_to_string(R[j]) + str(j)
        b[j] = int(sha256(my_string.encode()).hexdigest(), 16) % p
        L_ = b[j] * L[j]
        R_ = b[j] * R[j]
        P = P + L_ - b[j] * s[j] * g + R_ - b[j] * z[j] * IK_vector[j]

    ph_list = []
    for i in range(n):
        temp = b[0] * (PK[i][0] + H[i][0])
        for j in range(1, m):
            temp += b[j]*(PK[i][j] + H[i][j])
        ph_list.append(temp)
    
    if NISA_Verify(ph_list, P, c_number, pi) == 0:
        print("NISA CHECK FAILED")
        return 0

    my_string = M + catMultipleAddress(L, m) + catMultipleAddress(R, m)
    check = int(sha256(my_string.encode()).hexdigest(), 16) % p

    if c_number == check:
        return 1
    print("other check failed")
    return 0