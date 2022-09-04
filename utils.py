import secrets
from fastecdsa import keys, curve, ecdsa
from hashlib import sha256, sha512, sha384
from sympy import mod_inverse
from math import log2

my_curve = curve.W25519
g = my_curve.G
p = my_curve.q
generator_u = g * secrets.randbelow(p)

# key generation calling ecc keyGen
def KeyGen():
#     sk is before pk
    return keys.gen_keypair(my_curve)

# converting a ecc point to string form: taking its x and y coodinates
def pt_to_string(point):
    a = str(point.x)
    b = str(point.y)
    return a + b

# helper method to convert a list of numbers to a string
def list_to_string(l):
    a = ''
    for i in range (len(l)):
        a = a + str(l[i])
    return a

def HashToPoint(P):
    temp = pt_to_string(P)
    h = sha256(temp.encode()).hexdigest()
    H = int(h, 16) * g
    return H

def strHashToPoint(string):
    h = sha256(string.encode()).hexdigest()
    H = int(h, 16) * g
    return H

def Image_key(sk, PK):
    H = HashToPoint(PK)
    I = sk * H
    return I

def matrix_gen(n, m):
    matrix = [None] * n
    for i in range(n):
        matrix[i] = [None] * m
    return matrix

def catMultipleAddress(P, m):
    string = ''
    for i in range(m):
        string += pt_to_string(P[i])
    return string

# pk_list: public key list
# u: another generator
# b: at first a list of 1s
# a: list of all c in algorithm 4
# Loop in NISA Proof
def P_proof(pk_list, this_u, b, a, L, R):
#     start_time = time.time()
    n = len(a)
#     additional check
#     if len(a) != len(b) or len(a) != len(pk_list):
#         print("len check failed")
    if n == 1:
        return (L, R, a, b)
    
    n_prime = int(n / 2)
#     c_L and c_R should be two scalars
    c_L = 0
    c_R = 0
    for i in range (n_prime):
        c_R += ((a[n_prime + i] * b[i]) % p)
        c_L += ((a[i] * b[n_prime + i]) % p)
    
#     my_L and my_R should be two pts on ECC
    my_L = this_u * c_L
    my_R = this_u * c_R

#     print('stage 1 time: ', time.time() - start_time)
#     start_time = time.time()
    
    for ii in range (n_prime):
        my_L = my_L + (pk_list[n_prime + ii] * a[ii])
        my_R = my_R + (pk_list[ii] * a[n_prime + ii])
    L.append(my_L)
    R.append(my_R)
    my_string = pt_to_string(my_L) + pt_to_string(my_R)
    
#     print('stage 2 time: ', time.time() - start_time)
#     start_time = time.time()
    
#     x should be a number
    x = int(sha256(my_string.encode()).hexdigest(), 16)
#     pk_prime_list is g' in the algorithm
    pk_prime_list = [None] * n_prime
#     b_prime_list = [None] * n_prime
    a_prime_list = [None] * n_prime

    x_inverse = mod_inverse(x, p)
#    print('current x', x)
#    print('x_inverse ', x_inverse)
#   b[i] for every i in range should be the same value
    b_value = (x_inverse * b[0] + x * b[n_prime]) % p
    b_prime_list = [b_value] * n_prime
    for iii in range (n_prime):
        pk_prime_list[iii] = pk_list[iii] * x_inverse + pk_list[n_prime + iii] * x
        a_prime_list[iii] = (x * a[iii] + x_inverse * a[n_prime + iii]) % p
#        b_prime_list[iii] = (x * b[n_prime + iii] + x_inverse * b[iii]) % p
#     print('stage 3 time: ', time.time() - start_time)
#     start_time = time.time()
    
#     recursion
    return P_proof(pk_prime_list, this_u, b_prime_list, a_prime_list, L, R)



# helper method to check if (i -1)'s jth bit is a 1
def check_bit(i, j):
    temp = i
    if ((temp >> j) & 1) == 1:
        return 1
    return -1




# b: at first a list of 1s
# c is the summation of ci in DualRing
# pi: the returned product from P
# Loop in NISA Verify
def V(pk_list, this_u, P, pi):
    L = pi[0]
    R = pi[1]
    a = pi[2][0]
    b = pi[3][0]

    original_length = len(pk_list)
    log_length = int(log2(original_length))
    x_list = [None] * log_length
#     x_list is a list of hashed numbers
    for i in range (log_length):
        my_string = pt_to_string(L[i]) + pt_to_string(R[i])
        x_list[i] = int(sha256(my_string.encode()).hexdigest(), 16)
#        print('current x', x_list[i])
    y_list = [None] * original_length
#     y is a list of numbers 
    for ii in range (original_length):
        product = 1
        for iii in range (log_length):
            if check_bit(ii, iii) == 1:
                product = (product * x_list[log_length - iii - 1]) % p
            else:
                inverse = mod_inverse(x_list[log_length - iii - 1], p)
                product = (product * inverse) % p
        y_list[ii] = product
    g_prime = pk_list[0] * y_list[0]
    for iv in range (1, original_length):
        g_prime = g_prime + (pk_list[iv] * y_list[iv])
    left_check = P
    for v in range (log_length):
######################## (x_list[v] ** 2) % p is computed twice. Store it in a variable and reuse it ##########
        x_sq = (x_list[v] ** 2) % p
        left_check = left_check + (L[v] * x_sq)
        left_check = left_check + (R[v] * mod_inverse(x_sq, p))
    right_check = (g_prime + this_u * b)*a

    if left_check == right_check:
        return 1
    return 0


# P: a point on ECC
# a: a list of all Cs
def NISA_Proof(pk_list, P, c, a):
    my_string = pt_to_string(P) + pt_to_string(generator_u) + str(c)
    h = int(sha256(my_string.encode()).hexdigest(), 16)
    uprime = generator_u * h
    b = [1] * len(a)
    return P_proof(pk_list, uprime, b, a, [], [])


def NISA_Verify(pk_list, P, c, pi):
    my_string = pt_to_string(P) + pt_to_string(generator_u) + str(c)
    h = int(sha256(my_string.encode()).hexdigest(), 16)
    uprime = generator_u * h
    P_prime = P + uprime * c
    return V(pk_list, uprime, P_prime, pi)
