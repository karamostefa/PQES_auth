import hashlib
import random
import time
from time import perf_counter
import gmpy2
import secrets

def rfrag(x):
    x1 = secure_randint(2, x)
    x2 = x - x1
    return x1, x2


def egcd(a, b):
    x0, x1, y0, y1 = 1, 0, 0, 1
    while a != 0:
        q, r = divmod(b, a)
        b, a = a, r
        x0, x1 = x1 - q * x0, x0
        y0, y1 = y1 - q * y0, y0
    return b, x1, y1

def modinv(a, m):
    g, x, _ = egcd(a, m)
    if g != 1: return 0 # raise Exception('Modular inverse does not exist')
    else: return x % m


######
def modinv_shortcut(a, m):
    try:
        return pow(a, -1, m)
    except ValueError:
        return 0  # raise Exception('Modular inverse does not exist')

def secure_modinv(a, m):
    try:
        # gmpy2.invert calculates the modular inverse safely and efficiently
        # convert back to an int if your codebase expects a standard Python integer
        return int(gmpy2.invert(gmpy2.mpz(a), gmpy2.mpz(m)))
    except ZeroDivisionError:
        return 0  # gmpy2 throws ZeroDivisionError if the inverse doesn't exist

def secure_pow(base, exp, mod):
    """
    Calculates (base ** exp) % mod safely.
    - Hardened against side-channel timing attacks.
    - Highly optimized via gmpy2 C-bindings.
    """
    try:
        # 1. Convert all inputs to gmpy2's secure integer type (mpz)
        secure_base = gmpy2.mpz(base)
        secure_exp = gmpy2.mpz(exp)
        secure_mod = gmpy2.mpz(mod)
        
        # 2. Compute the modular exponentiation safely
        result = gmpy2.powmod(secure_base, secure_exp, secure_mod)
        
        # 3. Convert back to a standard Python integer
        return int(result)
        
    except ValueError:
        # Handles edge cases like a negative exponent when no modular inverse exists
        return 0

def secure_randint(a, b):
    """
    Returns a cryptographically secure random integer in the range [a, b] (inclusive).
    """
    if a > b:
        raise ValueError("The lower bound 'a' cannot be greater than the upper bound 'b'.")
    # 1. Calculate the size of the range (inclusive)
    range_size = (b - a) + 1
    # 2. Pick a secure random number from 0 up to (range_size - 1)
    random_offset = secrets.randbelow(range_size)
    # 3. Shift the number back up to start at 'a'
    return a + random_offset   
############   PQES scheme ############

# public param
p = 203956878356401977405765866929034577280193993314348263094772646453283062722701277632936616063144088173312372882677123879538709400158306567338328279154499698366071906766440037074217117805690872792848149112022286332144876183376326512083574821647933992961249917319836219304274280243803104015000563790123  # 995 prime
p1 = 97366961280791814622315360764926008528170871540390862931472370525788628065883 # 256 prime
g = 656692050181897513638241554199181923922955921760928836766304161790553989228223793461834703506872747071705167995972707253940099469869516422893633357693 #  500
n0 = 511704374946917490638851104912462284144240813125071454126151 # 200
# m: 200

# receiver param (Bob)
# receiver sk
s_b = 50000000001000000000000000000000000000000001000001000990099999000111000000064444      # 265 
e_b = 11099999999999999999999999299999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999099999999999912   # 731
k1_b = 19112880974989264961410958692689999885539995554677777856309606359249805529042  # 255 
k2_b = 76762880974989264961410958692689999885539995554677777856309606359249805529041  # 255 


# receiver pk
a_b = 987654321*p + 123456789#
b_b = (a_b*s_b + e_b) %p # 
K11_b = secure_pow(k1_b, k1_b, p1)  
K12_b = secure_pow(k1_b, k2_b, p1)

# sender param (Alice)
#sender sk
s_a = 30000000001000000000000000000000000000000001000001000990099999000111000000064444      # 265 
e_a = 88099999999999999999999999299999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999099999999999912   # 731
k1_a = 46222880974989264961410958692689999885539995554677777856309606359249805529042  # 255 
k2_a = 11122880974989264961410958692689999885539995554677777856309606359249805529041  # 255 

# sender pk
a_a = 127654321*p + 888456789#
b_a = (a_a*s_a + e_a) %p # 
K11_a = secure_pow(k1_a, k1_a, p1)  
K12_a = secure_pow(k1_a, k2_a, p1)  
  
  
# Conditions for PQES scheme ############

# 1: p1 < s .. ensure dec     e.g   256 - 265
# 2: p1*n*s < e .. ensure dec   e.g 721 - 731
# 3: e*p1 < p .. ensure dec   e.g   987 - 995
# 4: a > p .. employ mod
# security
# p1 large enough e.g., 256 bits
# k11,k12 size equiv p1:

#Alice
def enc_sig(n, p, p1, k1_a, k2_a, a_b, b_b):
    
    #h = hashlib.sha256(n.to_bytes(32, 'big')).hexdigest()
    h = hashlib.sha256(str.encode(str(n))).hexdigest()
    h = int(h,16) % p1
    #h1 = hashlib.sha256(h.to_bytes(32, 'big')).hexdigest()
    h1 = hashlib.sha256(str.encode(str(h))).hexdigest()
    h1 = int(h1,16) %p1
    
    x = secure_randint(2, p1)
    
    a2, b2 = rfrag(k2_a)
    a1 = (k1_a - a2)%(p1-1)
    b1 = (k1_a - b2)%(p1-1)
    
    s1 = secure_pow(k1_a, h*a1 + k1_a*x, p1)
    r1 = secure_pow(k1_a, (h*b1 + k1_a*(s1+h1-x))%(p1-1), p1)
    
    u = r1*(a_b - n) %p
    
    s2 = u*secure_pow(k1_a, (h*a2 + k1_a*(r1 - x))%(p1-1), p1) %p1
    r2 = secure_pow(s1, s2, p1)*secure_pow(k1_a, (h*b2 + k1_a*(s1-h1+r1+x))%(p1-1), p1) %p1
    
    v = r1*(b_b + r2) %p 
    
    return u,v,s1,s2, r1,r2

# Bob
def dec_verf(u, v, s1 ,s2 , p, p1, s_b, e_b, K11_a, K12_a):
    d = (v - u*s_b) %p
    r1 = d //e_b
    d1 = d %e_b
    d1 = d1 * secure_modinv(r1, p) %p
    n = d1 //s_b
    r2 = d1 %s_b
    #n_bytes_needed = (n.bit_length() + 7) // 8
    #h = hashlib.sha256(n.to_bytes(n_bytes_needed, 'big')).hexdigest()
    h = hashlib.sha256(str.encode(str(n))).hexdigest()
    h = int(h,16) %p1
    #h1 = hashlib.sha256(h.to_bytes(32, 'big')).hexdigest()
    h1 = hashlib.sha256(str.encode(str(h))).hexdigest()
    h1 = int(h1,16) %p1
    
    t = 1
    
    if r1*r2 %p1 != secure_pow(s1, s2, p1)*secure_pow(K11_a, h+2*s1+r1, p1) %p1: t = 0 #
    if s1*s2 %p1 != u*secure_pow(K11_a, r1 + h, p1) %p1: t = 0 #
    if s1*r1*secure_pow(K12_a, h, p1) %p1 != secure_pow(K11_a, s1+h1+2*h, p1) %p1: t = 0 #
    if s2*r2 %p1 != u*secure_pow(s1, s2, p1)*secure_pow(K11_a, (s1+2*r1-h1)%(p1-1), p1)*secure_pow(K12_a, h, p1) %p1: t = 0 #
    
    return n, t, r1, r2

# test: if t==1, Bob acceptes the msg 

####################### Proposed auth protocol, PQES based  #################################

#initialisation
CLOCK_DRIFT_WINDOW = 10
dbytes = b"||"
seq_a = 0
seq_b = 0  
bob_seen_seqs = set()  # Bob's replay log: stores (seq, ts) pairs seen from Alice
####

start_time = perf_counter()

# Alice auth
def auth_a(seq_a, p, p1, g, n0, k1_a, k2_a, a_b, b_b):
    xa =  secure_randint(g, p)
    Xa = secure_pow(g, xa, p)
    n = secure_randint(2, n0) # nonce
    u,v,s1,s2, r1,r2 = enc_sig(n, p, p1, k1_a, k2_a, a_b, b_b)
    M = (r1*Xa + r2) %p
    ts = int(time.time())
    hXa = hashlib.sha256(Xa.to_bytes(128, 'big')).hexdigest()
    ht = hashlib.sha256(r1.to_bytes(64, 'big') + dbytes + ts.to_bytes(8, 'big') + dbytes + n.to_bytes(32, 'big') + dbytes + seq_a.to_bytes(8, 'big')).digest()
    seq_a_sent = seq_a
    seq_a = seq_a + 1
    return n, u, v, s1, s2, M, hXa, xa, r1, r2, ts, ht, seq_a, seq_a_sent

n, u, v, s1, s2, M, hXa, xa, r1, r2, ts, ht, seq_a, seq_a_sent = auth_a(seq_a, p, p1, g, n0, k1_a, k2_a, a_b, b_b)

end_time = perf_counter()
print('time alice ver ', end_time-start_time) 

##### Round 1: Alice sends (c,σ,M,hXa,t_val) to Bob, c:(u,v), σ:(s1,s2) #####

start_time = perf_counter()
# Bob auth
def auth_b(seq_b, seq_a_sent, bob_seen_seqs, u, v, s1 ,s2 , M, hXa, ts, ht, p, p1, g, s_b, e_b, K11_a, K12_a):
    # Prune log — call periodically or at the start of auth_b
    current_ts = int(time.time())
    bob_seen_seqs = {(seq, t) for (seq, t) in bob_seen_seqs 
                 if abs(current_ts - t) < CLOCK_DRIFT_WINDOW}
    
    n_, t_, r1_, r2_ = dec_verf(u, v, s1 ,s2 , p, p1, s_b, e_b, K11_a, K12_a)
    if t_==1:
        Xa_ = secure_modinv(r1_, p)*(M - r2_) %p
        hXa_ = hashlib.sha256(Xa_.to_bytes(128, 'big')).hexdigest()
        ts_ = int(time.time())
        
        if seq_a_sent != seq_b:
            print('err: sequence mismatch'); return
        # Reject if (seq, ts) pair was seen before
        replay_key = (seq_a_sent, ts)
        if replay_key in bob_seen_seqs:
            print('err: replay detected'); return
        
        ht_ = hashlib.sha256(r1_.to_bytes(64, 'big') + dbytes + ts.to_bytes(8, 'big') + dbytes + n_.to_bytes(32, 'big') + dbytes + seq_b.to_bytes(8, 'big')).digest()
        if hXa_== hXa and ht == ht_ and abs(ts_ - ts) < CLOCK_DRIFT_WINDOW:
            # Log this (seq, ts) pair as consumed
            bob_seen_seqs.add(replay_key)
            
            xb =  secure_randint(g, p)
            Xb = secure_pow(g, xb, p)
            M_ = (r2_* Xb) %p ^ r1_ 
            hXb = hashlib.sha256(Xb.to_bytes(128, 'big')).hexdigest()
            DH_b = secure_pow(Xa_, xb, p)
            Z_b = hashlib.sha256(DH_b.to_bytes(128, 'big') + dbytes + n_.to_bytes(32, 'big') + dbytes + K11_a.to_bytes(64, 'big') + dbytes + K11_b.to_bytes(64, 'big') + dbytes + u.to_bytes(128, 'big') + dbytes + v.to_bytes(128, 'big') + dbytes + s1.to_bytes(64, 'big') + dbytes + s2.to_bytes(64, 'big')).digest() # session key 
            auth_bb = hashlib.sha256(K11_b.to_bytes(64, 'big') + dbytes + r2_.to_bytes(64, 'big') + dbytes + K12_b.to_bytes(64, 'big') + dbytes + Z_b).hexdigest() 
            seq_b = seq_b + 1 
            return M_, hXb, Z_b, auth_bb, seq_b, bob_seen_seqs
        else: print('err 1'); return
    else: print('err 2') ; return   

M_, hXb, Z_b, auth_bb, seq_b, bob_seen_seqs = auth_b(seq_b, seq_a_sent, bob_seen_seqs, u, v, s1 ,s2 , M, hXa, ts, ht, p, p1, g, s_b, e_b, K11_a, K12_a)
# Update log (ts, seq);  Bob must maintain a log of used (ts, seq) pairs and reject duplicates
            
end_time = perf_counter()
print('time bob ver ', end_time-start_time) 

###### Round 2: Bob sends M_, hXb, and auth_b to Alice ##########

start_time = perf_counter()
# Alice DH
def auth__a(n, p, p1, M_, hXb, xa, u, v, s1, s2, r1, r2, auth_bb, K11_b, K12_b):
    Xb_ = (secure_modinv(r2, p) * (M_ ^ r1)) %p
    hXb_ = hashlib.sha256(Xb_.to_bytes(128, 'big')).hexdigest()
    DH_a = secure_pow(Xb_, xa, p)
    Z_a = hashlib.sha256(DH_a.to_bytes(128, 'big') + dbytes + n.to_bytes(32, 'big') + dbytes + K11_a.to_bytes(64, 'big') + dbytes + K11_b.to_bytes(64, 'big') + dbytes + u.to_bytes(128, 'big') + dbytes + v.to_bytes(128, 'big') + dbytes + s1.to_bytes(64, 'big') + dbytes + s2.to_bytes(64, 'big')).digest() # session key 
    auth_b_ = hashlib.sha256(K11_b.to_bytes(64, 'big') + dbytes + r2.to_bytes(64, 'big') + dbytes + K12_b.to_bytes(64, 'big') + dbytes + Z_a).hexdigest()  
            
    if hXb_==hXb and auth_b_ == auth_bb: 
        # send confirmation to Bob HMAC(Z_a, 'confirm')
        return Z_a
    else: print('err 3'); return
    
Z_a = auth__a(n, p, p1, M_, hXb, xa, u, v, s1, s2, r1, r2, auth_bb, K11_b, K12_b)  

if Z_a == Z_b: print('seccess!')

end_time = perf_counter()
print('time alice2 ver ', end_time-start_time) 



#m = random.randint(pow(10,59), pow(10,60))  # m: 200
#m = 999999999999999999993453634636363634634634634634699999999991 # m: 200

#start_time = perf_counter()
#u,v,s1,s2, r1,r2 = enc_sig(m, p, p1, k1_a, k2_a, a_b, b_b)
#end_time = perf_counter()
#print('time enc sig ', end_time-start_time) 

#start_time = perf_counter()
#mm, tt, rr1, rr2 = dec_verf(u, v, s1 ,s2 , p, p1, s_b, e_b, K11_a, K12_a)
#end_time = perf_counter()
#print('time dec ver ', end_time-start_time) 

#if mm == m: print("dec correct, t =",tt) 




