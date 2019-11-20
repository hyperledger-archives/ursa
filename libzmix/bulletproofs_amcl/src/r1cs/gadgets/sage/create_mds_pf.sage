# For GF(p)

if len(sys.argv) < 4:
    print "Usage: <script> <N> <t> <prime_number_hex>"
    exit()

N = int(sys.argv[1])
t = int(sys.argv[2])
prime = int(sys.argv[3], 16) # e.g. hex(2^249 - 15145038707218910765482344729778085401) for n = 249
n = int(N / t)

F.<x> = GF(prime)

def isAllInvertible(M, t):
    # Test all square submatrices for invertibility
    counter = 0
    all_invertible = True
    for i in range(2, t):
        choices_i = Combinations(range(0, t), i)
        for m in range(0, choices_i.cardinality()):
            for n in range(0, choices_i.cardinality()):
                M_sub = M[choices_i[m], choices_i[n]]
                is_inv = M_sub.is_invertible()
                all_invertible = all_invertible and is_inv
                if is_inv == False:
                    print "FALSE"
                    print M_sub
                counter += 1
    print "Submatrices checked:", counter
    return all_invertible

def print_matrix_format(M_int, n, t):
    print "n:", n
    print "t:", t
    print "N:", (n * t)
    print "Prime:", "0x" + hex(prime)
    hex_length = int(ceil(float(n) / 4)) + 2 # +2 for "0x"
    print "MDS matrix (rows):"
    for i in range(0, t):
        #print [hex(entry) for entry in M_int[i]]
        print ["{0:#0{1}x}".format(entry, hex_length) for entry in M_int[i]]

def matrix_entries_to_int(M, t):
    M_int = []
    for i in range(0, t):
        M_int.append([])
        for j in range(0, t):
            M_int[i].append(int(M[i, j]))
    return M_int

def create_mds(n, t, start):
    M = matrix(F, t, t)
    xs = []
    ys = []
    
    for i in range(0, t):
        xs.append(F(start + i))
        ys.append(F(start + t + i))
    
    for i in range(0, t):
        for j in range(0, t):
            entry = (xs[i] + ys[j])^(-1)
            M[i, j] = entry
    return M
    
mds_matrix = create_mds(n, t, 0)
mds_matrix_int = matrix_entries_to_int(mds_matrix, t)
print_matrix_format(mds_matrix_int, n, t)