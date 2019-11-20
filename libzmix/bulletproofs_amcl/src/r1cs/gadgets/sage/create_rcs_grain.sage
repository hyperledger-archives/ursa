from sage.rings.polynomial.polynomial_gf2x import GF2X_BuildIrred_list

# GF(p), x^3, N = 1536, n = 64, t = 24: sage create_rcs_grain.sage 1 0 64 24 8 42 0xfffffffffffffeff
# GF(p), x^(-1), N = 1518, n = 253, t = 6: sage create_rcs_grain.sage 1 2 253 6 8 127 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed
# GF(2^n), x^3, N = 1512, n = 63, t = 24: sage create_rcs_grain.sage 0 0 63 24 8 45

if len(sys.argv) < 7:
    print "Usage: <script> <field> <s_box> <field_size> <num_cells> <R_F> <R_P> (<prime_number_hex>)"
    print "field = 0 for GF(2^n), field = 1 for GF(p)"
    print "s_box = 0 for x^3, s_box = 1 for x^5, s_box = 2 for x^(-1)"
    exit()

# Parameters
FIELD = int(sys.argv[1]) # 0 .. GF(2^n), 1 .. GF(p)
SBOX = int(sys.argv[2]) # 0 .. x^3, 1 .. x^5, 2 .. x^(-1)
FIELD_SIZE = int(sys.argv[3]) # n
NUM_CELLS = int(sys.argv[4]) # t
R_F_FIXED = int(sys.argv[5])
R_P_FIXED = int(sys.argv[6])

INIT_SEQUENCE = []

PRIME_NUMBER = 0
if FIELD == 1 and len(sys.argv) != 8:
    print "Please specify a prime number (in hex format)!"
    exit()
elif FIELD == 1 and len(sys.argv) == 8:
    PRIME_NUMBER = int(sys.argv[7], 16) # e.g. 0xa7, 0xFFFFFFFFFFFFFEFF, 0xa1a42c3efd6dbfe08daa6041b36322ef

def grain_sr_generator():
    bit_sequence = INIT_SEQUENCE
    for _ in range(0, 160):
        new_bit = bit_sequence[62] ^^ bit_sequence[51] ^^ bit_sequence[38] ^^ bit_sequence[23] ^^ bit_sequence[13] ^^ bit_sequence[0]
        bit_sequence.pop(0)
        bit_sequence.append(new_bit)
        
    while True:
        new_bit = bit_sequence[62] ^^ bit_sequence[51] ^^ bit_sequence[38] ^^ bit_sequence[23] ^^ bit_sequence[13] ^^ bit_sequence[0]
        bit_sequence.pop(0)
        bit_sequence.append(new_bit)
        while new_bit == 0:
            new_bit = bit_sequence[62] ^^ bit_sequence[51] ^^ bit_sequence[38] ^^ bit_sequence[23] ^^ bit_sequence[13] ^^ bit_sequence[0]
            bit_sequence.pop(0)
            bit_sequence.append(new_bit)
            new_bit = bit_sequence[62] ^^ bit_sequence[51] ^^ bit_sequence[38] ^^ bit_sequence[23] ^^ bit_sequence[13] ^^ bit_sequence[0]
            bit_sequence.pop(0)
            bit_sequence.append(new_bit)
        new_bit = bit_sequence[62] ^^ bit_sequence[51] ^^ bit_sequence[38] ^^ bit_sequence[23] ^^ bit_sequence[13] ^^ bit_sequence[0]
        bit_sequence.pop(0)
        bit_sequence.append(new_bit)
        yield new_bit
grain_gen = grain_sr_generator()
        
def grain_random_bits(num_bits):
    random_bits = [grain_gen.next() for i in range(0, num_bits)]
    random_int = int("".join(str(i) for i in random_bits), 2)
    return random_int

def generate_constants(field, sbox, n, t, R_F, R_P, prime_number):
    round_constants = []
    num_constants = (R_F + R_P) * t
    print "R_F:", R_F
    print "R_P:", R_P
    print "# Constants:", num_constants
    # Generate initial sequence based on parameters
    bit_list_field = [_ for _ in (bin(FIELD)[2:].zfill(2))]
    bit_list_sbox = [_ for _ in (bin(SBOX)[2:].zfill(4))]
    bit_list_n = [_ for _ in (bin(FIELD_SIZE)[2:].zfill(12))]
    bit_list_t = [_ for _ in (bin(NUM_CELLS)[2:].zfill(12))]
    bit_list_R_F = [_ for _ in (bin(R_F)[2:].zfill(10))]
    bit_list_R_P = [_ for _ in (bin(R_P)[2:].zfill(10))]
    bit_list_1 = [1] * 30
    global INIT_SEQUENCE
    INIT_SEQUENCE = bit_list_field + bit_list_sbox + bit_list_n + bit_list_t + bit_list_R_F + bit_list_R_P + bit_list_1
    INIT_SEQUENCE = [int(_) for _ in INIT_SEQUENCE]

    if field == 0:
        for i in range(0, num_constants):
            random_int = grain_random_bits(n)
            round_constants.append(random_int)
        print "Round constants for GF(2^n):"
    elif field == 1:
        for i in range(0, num_constants):
            random_int = grain_random_bits(n)
            while random_int >= prime_number:
                # print "[Info] Round constant is not in prime field! Taking next one."
                random_int = grain_random_bits(n)
            round_constants.append(random_int)
        print "Round constants for GF(p):"
    hex_length = int(ceil(float(n) / 4)) + 2 # +2 for "0x"
    print ["{0:#0{1}x}".format(entry, hex_length) for entry in round_constants]


generate_constants(FIELD, SBOX, FIELD_SIZE, NUM_CELLS, R_F_FIXED, R_P_FIXED, PRIME_NUMBER)