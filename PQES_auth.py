
# Conditions for PQES scheme ############

# 1: p1 < s .. ensure dec     e.g   256 - 265
# 2: p1*n*s < e .. ensure dec   e.g 721 - 731
# 3: e*p1 < p .. ensure dec   e.g   987 - 995
# 4: a > p .. employ mod
# security
# p1 large enough e.g., 256 bits
# k11,k12 size equiv p1:


import hashlib
import time
from time import perf_counter
import gmpy2
import secrets
from typing import List, Tuple
import json
import os

# --- AUTOMATIC SCRIPT INITIALIZATION CLEANUP ---
# This ensures that when you run the standalone script, old state doesn't cause a sequence desync
NVRAM_FILE = "bob_nvram_state.json"
if os.path.exists(NVRAM_FILE):
    os.remove(NVRAM_FILE)

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
    if g != 1: return 0 
    else: return x % m

def secure_modinv(a, m):
    try:
        return int(gmpy2.invert(gmpy2.mpz(a), gmpy2.mpz(m)))
    except ZeroDivisionError:
        return 0 

def secure_pow(base, exp, mod):
    try:
        secure_base = gmpy2.mpz(base)
        secure_exp = gmpy2.mpz(exp)
        secure_mod = gmpy2.mpz(mod)
        result = gmpy2.powmod(secure_base, secure_exp, secure_mod)
        return int(result)
    except ValueError:
        return 0

def secure_randint(a, b):
    if a > b:
        raise ValueError("The lower bound 'a' cannot be greater than the upper bound 'b'.")
    range_size = (b - a) + 1
    random_offset = secrets.randbelow(range_size)
    return a + random_offset 

def save_to_nvram(seq_b: int, seen_timestamps: List[float]) -> None:
    """Simulates an atomic write-ahead log flush to NVRAM storage."""
    state = {
        "seq_b": seq_b,
        "seen_timestamps": seen_timestamps
    }
    with open(NVRAM_FILE, "w") as f:
        json.dump(state, f)
        f.flush()
        try:
            os.fsync(f.fileno())
        except OSError:
            pass

def load_from_nvram() -> Tuple[int, List[float]]:
    """Simulates booting up and recovering protocol state boundaries from NVRAM."""
    if not os.path.exists(NVRAM_FILE):
        return 0, []
    try:
        with open(NVRAM_FILE, "r") as f:
            state = json.load(f)
            return state.get("seq_b", 0), state.get("seen_timestamps", [])
    except (json.JSONDecodeError, IOError):
        return 0, []

############  PQES scheme ############

# public param
p = 203956878356401977405765866929034577280193993314348263094772646453283062722701277632936616063144088173312372882677123879538709400158306567338328279154499698366071906766440037074217117805690872792848149112022286332144876183376326512083574821647933992961249917319836219304274280243803104015000563790123  # 995 prime
p1 = 97366961280791814622315360764926008528170871540390862931472370525788628065883 # 256 prime
g = 656692050181897513638241554199181923922955921760928836766304161790553989228223793461834703506872747071705167995972707253940099469869516422893633357693 #  500
n0 = 511704374946917490638851104912462284144240813125071454126151 # 200

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
BobID = 123

# sender param (Alice)
#sender sk
s_a = 30000000001000000000000000000000000000000001000001000990099999000111000000064444      # 265 
e_a = 88099999999999999999999999299999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999099999999999912   # 731
k1_a = 46222880974989264961410958692689999885539995554677777856309606359249805529042  # 255 
k2_a = 11122880974989264961410958692689999885539995554677777856309606359249805529041  # 255 

# sender pk
a_a = 127654321*p + 888456789
b_a = (a_a*s_a + e_a) %p  
K11_a = secure_pow(k1_a, k1_a, p1)  
K12_a = secure_pow(k1_a, k2_a, p1)
AliceID = 124  
   
  
def enc_sig(n, p, p1, k1_a, k2_a, a_b, b_b):
    h = hashlib.sha256(str.encode(str(n))).hexdigest()
    h = int(h,16) % p1
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

def dec_verf(u, v, s1 ,s2 , p, p1, s_b, e_b, K11_a, K12_a):
    d = (v - u*s_b) %p
    r1 = d //e_b
    d1 = d %e_b
    d1 = d1 * secure_modinv(r1, p) %p
    n = d1 //s_b
    r2 = d1 %s_b
    
    h = hashlib.sha256(str.encode(str(n))).hexdigest()
    h = int(h,16) %p1
    h1 = hashlib.sha256(str.encode(str(h))).hexdigest()
    h1 = int(h1,16) %p1
    
    t = 1
    
    if r1*r2 %p1 != secure_pow(s1, s2, p1)*secure_pow(K11_a, h+2*s1+r1, p1) %p1: t = 0 
    if s1*s2 %p1 != u*secure_pow(K11_a, r1 + h, p1) %p1: t = 0 
    if s1*r1*secure_pow(K12_a, h, p1) %p1 != secure_pow(K11_a, s1+h1+2*h, p1) %p1: t = 0 
    if s2*r2 %p1 != u*secure_pow(s1, s2, p1)*secure_pow(K11_a, (s1+2*r1-h1)%(p1-1), p1)*secure_pow(K12_a, h, p1) %p1: t = 0 
    
    return n, t, r1, r2

####################### Proposed auth protocol, PQES based  #################################

CLOCK_DRIFT_WINDOW = 30  
dbytes = b"||"
seq_a = 0

start_time = perf_counter()

def auth_a(seq_a, p, p1, g, n0, k1_a, k2_a, a_b, b_b):
    xa = secure_randint(g, p)
    Xa = secure_pow(g, xa, p)
    n = secure_randint(2, n0) 
    u, v, s1, s2, r1, r2 = enc_sig(n, p, p1, k1_a, k2_a, a_b, b_b)
    M = (r1*Xa + r2) %p
    ts = int(time.time())
    hXa = hashlib.sha256(Xa.to_bytes(128, 'big') + dbytes + M.to_bytes(128, 'big')).hexdigest()
    ht = hashlib.sha256(r1.to_bytes(64, 'big') + dbytes + ts.to_bytes(8, 'big') + dbytes + n.to_bytes(32, 'big') + dbytes + seq_a.to_bytes(8, 'big')).digest()
    seq_a_sent = seq_a
    seq_a = seq_a + 1
    return n, u, v, s1, s2, M, hXa, xa, r1, r2, ts, ht, seq_a, seq_a_sent

n, u, v, s1, s2, M, hXa, xa, r1, r2, ts, ht, seq_a, seq_a_sent = auth_a(seq_a, p, p1, g, n0, k1_a, k2_a, a_b, b_b)

end_time = perf_counter()
print('time alice ver ', end_time-start_time) 

##### Round 1: Alice sends (c,σ,M,hXa,ts,ht) to Bob #####

start_time = perf_counter()

def auth_b(seq_a_sent, u, v, s1 ,s2 , M, hXa, ts, ht, p, p1, g, s_b, e_b, K11_a, K12_a):
    n_, t_, r1_, r2_ = dec_verf(u, v, s1 ,s2 , p, p1, s_b, e_b, K11_a, K12_a)
    if t_==1:
        Xa_ = secure_modinv(r1_, p)*(M - r2_) %p
        hXa_ = hashlib.sha256(Xa_.to_bytes(128, 'big') + dbytes + M.to_bytes(128, 'big')).hexdigest()
        
        ts_ = int(time.time())
        seq_b, bob_seen_ts = load_from_nvram()
        
        if abs(ts_ - ts) > CLOCK_DRIFT_WINDOW: return None
        if ts in bob_seen_ts or seq_a_sent < seq_b: return None 
                
        ht_ = hashlib.sha256(r1_.to_bytes(64, 'big') + dbytes + ts.to_bytes(8, 'big') + dbytes + n_.to_bytes(32, 'big') + dbytes + seq_a_sent.to_bytes(8, 'big')).digest()
        
        if hXa_== hXa and ht == ht_:
            xb = secure_randint(g, p)
            Xb = secure_pow(g, xb, p)
            M_ = (r2_* Xb) %p ^ r1_ 
            hXb = hashlib.sha256(Xb.to_bytes(128, 'big') + dbytes + M_.to_bytes(128, 'big')).hexdigest()
            
            DH_b = secure_pow(Xa_, xb, p)
            Z_b = hashlib.sha256(AliceID.to_bytes(2, 'big') + b"||" + BobID.to_bytes(2, 'big') + b"||" + DH_b.to_bytes(128, 'big') + dbytes + n_.to_bytes(32, 'big') + dbytes + K11_a.to_bytes(64, 'big') + dbytes + K11_b.to_bytes(64, 'big') + dbytes + u.to_bytes(128, 'big') + dbytes + v.to_bytes(128, 'big') + dbytes + s1.to_bytes(64, 'big') + dbytes + s2.to_bytes(64, 'big')).digest() 
            
            kmac_b = hashlib.sha256(Z_b + b"||server_finished").digest()
            
            # Compute a MAC token over the unique ephemeral public parameters and identities
            transcript_b = (
                Xb.to_bytes(128, 'big') + dbytes + 
                Xa_.to_bytes(128, 'big') + dbytes + 
                K11_b.to_bytes(64, 'big') + dbytes + 
                K12_b.to_bytes(64, 'big')
            )
            auth_bb = hashlib.sha256(kmac_b + dbytes + transcript_b).hexdigest() 
            
            seq_b = seq_a_sent + 1 
            bob_seen_ts.append(ts)
            bob_seen_ts = [t for t in bob_seen_ts if abs(ts_ - t) <= CLOCK_DRIFT_WINDOW]
            save_to_nvram(seq_b, bob_seen_ts) 
            
            return M_, hXb, Z_b, auth_bb
        else: return None
    else: return None   

# Safe unpack check sequence
auth_b_result = auth_b(seq_a_sent, u, v, s1 ,s2 , M, hXa, ts, ht, p, p1, g, s_b, e_b, K11_a, K12_a)

if auth_b_result is None:
    print("Execution halted due to validation failure inside auth_b.")
    Z_b = None
else:
    M_, hXb, Z_b, auth_bb = auth_b_result
    end_time = perf_counter()
    print('time bob ver ', end_time-start_time) 

###### Round 2: Bob sends M_, hXb, and auth_bb to Alice ##########

if Z_b is not None:
    start_time = perf_counter()
    def auth__a(n, p, p1, M_, hXb, xa, u, v, s1, s2, r1, r2, auth_bb, K11_b, K12_b):
        Xb_ = (secure_modinv(r2, p) * (M_ ^ r1)) %p
        hXb_ = hashlib.sha256(Xb_.to_bytes(128, 'big') + dbytes + M_.to_bytes(128, 'big')).hexdigest()
        
        Xa = secure_pow(g, xa, p)
        
        DH_a = secure_pow(Xb_, xa, p)
        Z_a = hashlib.sha256(AliceID.to_bytes(2, 'big') + b"||" + BobID.to_bytes(2, 'big') + b"||" + DH_a.to_bytes(128, 'big') + dbytes + n.to_bytes(32, 'big') + dbytes + K11_a.to_bytes(64, 'big') + dbytes + K11_b.to_bytes(64, 'big') + dbytes + u.to_bytes(128, 'big') + dbytes + v.to_bytes(128, 'big') + dbytes + s1.to_bytes(64, 'big') + dbytes + s2.to_bytes(64, 'big')).digest() 
        
        kmac_a = hashlib.sha256(Z_a + b"||server_finished").digest()
        
        transcript_a = (
            Xb_.to_bytes(128, 'big') + dbytes + 
            Xa.to_bytes(128, 'big') + dbytes + 
            K11_b.to_bytes(64, 'big') + dbytes + 
            K12_b.to_bytes(64, 'big')
        )
        auth_b_ = hashlib.sha256(kmac_a + dbytes + transcript_a).hexdigest()  
                
        if hXb_ == hXb and auth_b_ == auth_bb: 
            return Z_a
        else: return None
        
    Z_a = auth__a(n, p, p1, M_, hXb, xa, u, v, s1, s2, r1, r2, auth_bb, K11_b, K12_b)  

    if Z_a == Z_b: 
        print('success!')

    end_time = perf_counter()
    print('time alice2 ver ', end_time-start_time)
    
###### Round 3 if needed: Alice sends HMAC(Z, "Alice finished") ##########
