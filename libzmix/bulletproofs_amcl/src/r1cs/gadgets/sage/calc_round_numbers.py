from math import *
import sys

if len(sys.argv) != 6:
    print "Usage: <script> <N> <t> <M> <field_case> <sbox_case>"
    print "field_case: 0 (binary), 1 (prime)"
    print "sbox_case: 0 (x^3), 1 (x^5), 2 (x^(-1))"
    exit()

N_fixed = int(sys.argv[1])
t_fixed = int(sys.argv[2])
M = int(sys.argv[3]) # Security level
field_case = int(sys.argv[4])
sbox_case = int(sys.argv[5])

if N_fixed % t_fixed != 0:
    print "t is not a divisor of N!"
    exit()

if field_case == 0:
    n = int(ceil(float(N_fixed) / t_fixed))
    if n % 2 == 0:
        n_new = n + 1
        N_fixed = int(n_new * t_fixed)
print "N:", N_fixed
print "Security level M:", M

if field_case == 0:
    print "Field: Binary"
else:
    print "Field: Prime"

if sbox_case == 0:
    print "S-box: f(x) = x^3"
elif sbox_case == 1:
    print "S-box: f(x) = x^5"
elif sbox_case == 2:
    print "S-box: f(x) = x^(-1)"

def sat_inequiv_cubic(N, t, R_F, R_P):
    n = ceil(float(N) / t)
    R_F_1 = 6 if ((t + 1) <= (N + n - M)) else 10 # Statistical
    R_F_2 = 0.63 * min(n, M) + log(t, 2) - R_P # Interpolation
    R_F_3 = 0.32 * min(n, M) - R_P # Groebner 1
    R_F_4 = float(0.18 * min(n, M) - 1 - R_P) / (t - 1) # Groebner 2
    R_F_5 = (0.63 * min(n, M) + 2 + log(t, 2) - R_P) if (field_case == 0) else 0
    R_F_max = max(ceil(R_F_1), ceil(R_F_2), ceil(R_F_3), ceil(R_F_4), ceil(R_F_5))
    if R_F >= R_F_max:
        return True
    else:
        return False

def sat_inequiv_fifth(N, t, R_F, R_P):
    n = ceil(float(N) / t)
    R_F_1 = 6 if ((2 * (t + 1)) <= (N + n - M)) else 10 # Statistical
    R_F_2 = 0.43 * min(n, M) + log(t, 2) - R_P # Interpolation
    R_F_3 = 0.21 * min(n, M) - R_P # Groebner 1
    R_F_4 = float(0.14 * min(n, M) - 1 - R_P) / (t - 1) # Groebner 2
    R_F_5 = (0.63 * min(n, M) + 2 + log(t, 2) - R_P) if (field_case == 0) else 0
    R_F_max = max(ceil(R_F_1), ceil(R_F_2), ceil(R_F_3), ceil(R_F_4), ceil(R_F_5))
    if R_F >= R_F_max:
        return True
    else:
        return False

def sat_inequiv_inverse(N, t, R_F, R_P):
    n = ceil(float(N) / t)
    R_F_1 = 6 if ((2 * (t + 1)) <= (N + n - M)) else 10 # Statistical
    R_P_1 = 2 + log(t, 2) + min(n, M) - log(t, 2) * R_F # Interpolation
    R_F_2 = float(log(t, 2) + 0.5 * min(n, M) - R_P) / log(t, 2) # Groebner 1
    R_F_3 = float(0.25 * min(n, M) - 1 - R_P) / (t - 1) # Groebner 2
    R_F_4 = (0.63 * min(n, M) + 2 + log(t, 2) - R_P) if (field_case == 0) else 0
    R_F_max = max(ceil(R_F_1), ceil(R_F_2), ceil(R_F_3), ceil(R_F_4))
    R_P_max = ceil(R_P_1)
    if R_F >= R_F_max and R_P >= R_P_max:
        return True
    else:
        return False

def get_sbox_cost(R_F, R_P, N, t):
    return int(t * R_F + R_P)

def get_size_cost(R_F, R_P, N, t):
    n = ceil(float(N) / t)
    return int((N * R_F) + (n * R_P))

def find_FD_round_numbers(N, t, cost_function, security_margin):
    sat_inequiv = None
    if sbox_case == 0:
        sat_inequiv = sat_inequiv_cubic
    elif sbox_case == 1:
        sat_inequiv = sat_inequiv_fifth
    elif sbox_case == 2:
        sat_inequiv = sat_inequiv_inverse

    R_P = 0
    R_F = 0
    min_cost = float("inf")
    max_cost_rf = 0
    # Brute-force approach
    for R_P_t in range(1, 1000):
        for R_F_t in range(4, 200):
            if R_F_t % 2 == 0:
                if (sat_inequiv(N, t, R_F_t, R_P_t) == True):
                    if security_margin == True:
                        R_F_t += 2
                        R_P_t = int(ceil(float(R_P_t) * 1.075))
                    cost = cost_function(R_F_t, R_P_t, N, t)
                    if (cost < min_cost) or ((cost == min_cost) and (R_F_t < max_cost_rf)):
                        R_P = ceil(R_P_t)
                        R_F = ceil(R_F_t)
                        min_cost = cost
                        max_cost_rf = R_F
    return (int(R_F), int(R_P))

def calc_final_numbers_fixed(security_margin):
    # [Min. S-boxes] Find best possible for t_fixed and N_fixed
    ret_list = []
    (R_F, R_P) = find_FD_round_numbers(N_fixed, t_fixed, get_sbox_cost, security_margin)
    min_sbox_cost = get_sbox_cost(R_F, R_P, N_fixed, t_fixed)
    ret_list.append(R_F)
    ret_list.append(R_P)
    ret_list.append(min_sbox_cost)

    # [Min. Size] Find best possible for t_fixed and N_fixed
    # Minimum number of S-boxes for fixed n results in minimum size also (round numbers are the same)!
    min_size_cost = get_size_cost(R_F, R_P, N_fixed, t_fixed)
    ret_list.append(min_size_cost)

    return ret_list # [R_F, R_P, min_sbox_cost, min_size_cost]

def print_latex_table_combinations(combinations, security_margin):
    global N_fixed
    global t_fixed
    global M
    global field_case
    global sbox_case
    field_string = ""
    sbox_string = ""
    for comb in combinations:
        N_fixed = comb[0]
        t_fixed = comb[1]
        M = comb[2]
        field_case = comb[3]
        sbox_case = comb[4]
        n = int(ceil(float(N_fixed) / t_fixed))
        ret = calc_final_numbers_fixed(security_margin)
        if field_case == 0:
            field_string = "\mathbb F_{2^n}"
        elif field_case == 1:
            field_string = "\mathbb F_{p}"
        if sbox_case == 0:
            sbox_string = "x^3"
        elif sbox_case == 1:
            sbox_string = "x^5"
        elif sbox_case == 2:
            sbox_string = "x^{-1}"
        print "$" + str(M) + "$ & $" + str(N_fixed) + "$ & $" + str(n) + "$ & $" + str(t_fixed) + "$ & $" + str(ret[0]) + "$ & $" + str(ret[1]) + "$ & $" + field_string + "$ & $" + str(ret[2]) + "$ & $" + str(ret[3]) + "$ \\\\"

def print_pretty_combinations(combinations, security_margin):
    global N_fixed
    global t_fixed
    global M
    global field_case
    global sbox_case
    field_string = ""
    sbox_string = ""
    print "Format: [Security Level, Field Size, # Elements, Field, S-Box, R_F, R_P]"
    for comb in combinations:
        N_fixed = comb[0]
        t_fixed = comb[1]
        M = comb[2]
        field_case = comb[3]
        sbox_case = comb[4]
        n = int(ceil(float(N_fixed) / t_fixed))
        ret = calc_final_numbers_fixed(security_margin)
        if field_case == 0:
            field_string = "GF(2^n)"
        elif field_case == 1:
            field_string = "GF(p)"
        if sbox_case == 0:
            sbox_string = "x^3"
        elif sbox_case == 1:
            sbox_string = "x^5"
        elif sbox_case == 2:
            sbox_string = "x^{-1}"
        print [str(M), str(n), str(t_fixed), field_string, sbox_string, str(ret[0]), str(ret[1])]

ret_fixed = calc_final_numbers_fixed(True)
print ret_fixed
print "Recommendation for N=" + str(N_fixed) + ", t=" + str(t_fixed) + ":"
print "R_F =", ret_fixed[0]
print "R_P =", ret_fixed[1]
print "S-box cost =", ret_fixed[2]
print "Size cost =", ret_fixed[3]

# Table for challenge
# Format: [N, t, M, field, s_box]
# --> [N, t, M, 0/1, 0] (binary/prime field and x^3)
combinations_challenge = [
    [3*45, 3, 45, 0, 0],
    [3*45, 3, 45, 1, 0],
    [3*90, 3, 45, 0, 0],
    [3*90, 3, 45, 1, 0],
    [4*80, 4, 80, 0, 0],
    [4*80, 4, 80, 1, 0],
    [3*160, 3, 80, 0, 0],
    [3*160, 3, 80, 1, 0],
    [11*160, 11, 80, 0, 0],
    [11*160, 11, 80, 1, 0],
    [4*128, 4, 128, 0, 0],
    [4*128, 4, 128, 1, 0],
    [3*256, 3, 128, 0, 0],
    [3*256, 3, 128, 1, 0],
    [12*128, 12, 128, 0, 0],
    [12*128, 12, 128, 1, 0],
    [11*256, 11, 128, 0, 0],
    [11*256, 11, 128, 1, 0],
    [8*128, 8, 256, 0, 0],
    [8*128, 8, 256, 1, 0],
    [3*512, 3, 256, 0, 0],
    [3*512, 3, 256, 1, 0],
    [14*128, 14, 256, 0, 0],
    [14*128, 14, 256, 1, 0],
    [11*512, 11, 256, 0, 0],
    [11*512, 11, 256, 1, 0],
]

print "--- Round numbers (with security margin) ---"
print_pretty_combinations(combinations_challenge, True)
exit()

# Build table
# x^3
x_3_combinations = [
    [1536, 2, 128, 1, 0], [1536, 4, 128, 1, 0], [1536, 6, 128, 1, 0], [1536, 8, 128, 1, 0], [1536, 16, 128, 1, 0],
    [1512, 24, 128, 0, 0], [1551, 47, 128, 0, 0], [1581, 51, 128, 0, 0],
    [1536, 2, 256, 1, 0], [1536, 4, 256, 1, 0], [1536, 6, 256, 1, 0], [1536, 8, 256, 1, 0], [1536, 16, 256, 1, 0],
    [1512, 24, 256, 0, 0], [1551, 47, 256, 0, 0], [1581, 51, 256, 0, 0]
]

# With security margin
print "--- Table x^3 WITH security margin ---"
print_latex_table_combinations(x_3_combinations, True)

# Without security margin
print "--- Table x^3 WITHOUT security margin ---"
print_latex_table_combinations(x_3_combinations, False)

# x^5
x_5_combinations = [
    [1536, 2, 128, 1, 1], [1536, 4, 128, 1, 1], [1536, 6, 128, 1, 1], [1536, 8, 128, 1, 1], [1536, 16, 128, 1, 1],
    [1536, 2, 256, 1, 1], [1536, 4, 256, 1, 1], [1536, 6, 256, 1, 1], [1536, 8, 256, 1, 1], [1536, 16, 256, 1, 1]
]

# With security margin
print "--- Table x^5 WITH security margin ---"
print_latex_table_combinations(x_5_combinations, True)

# Without security margin
print "--- Table x^5 WITHOUT security margin ---"
print_latex_table_combinations(x_5_combinations, False)

# x^{-1}
x_inv_combinations = [
    [1536, 2, 128, 1, 2], [1536, 4, 128, 1, 2], [1536, 6, 128, 1, 2], [1536, 8, 128, 1, 2], [1536, 16, 128, 1, 2],
    [1536, 2, 256, 1, 2], [1536, 4, 256, 1, 2], [1536, 6, 256, 1, 2], [1536, 8, 256, 1, 2], [1536, 16, 256, 1, 2]
]

# With security margin
print "--- Table x^{-1} WITH security margin ---"
print_latex_table_combinations(x_inv_combinations, True)

# Without security margin
print "--- Table x^{-1} WITHOUT security margin ---"
print_latex_table_combinations(x_inv_combinations, False)
