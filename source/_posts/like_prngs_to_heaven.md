---
date: 2025-06-13
title: "bi0sCTF 2025 Crypto ...Like PRNGS to Heaven"
toc: true
cover: /images/covers/like_prngs_to_heaven_top.jpg
description: "Writeup on my bi0sCTF challenge"
math: true
aside: true
tags: 
- Lattice
- PRNG
- Z3
- EHNP
categories: Writeup
---


### Challenge Description

```
"You hunger to claim victory in a war that ended without you."
```

### Introduction

This is the challenge I made for bi0sCTF 2025. I wanted to make an EHNP instance challenge for sometime now so I made it with some *Ultrakill* theme

### Given information

#### chall.py

```python
from tinyec.ec import SubGroup, Curve
from RMT import R_MT19937_32bit as special_random
from decor import HP, death_message, menu_box, title_drop
from Crypto.Util.number import bytes_to_long as b2l
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random.random import getrandbits
from hashlib import sha256
from json import loads
import sys
import os
from secret import FLAG

CORE = 0xb4587f9bd72e39c54d77b252f96890f2347ceff5cb6231dfaadb94336df08dfd

class _1000_THR_Signing_System:
    def __init__(self):
        # secp256k1 
        self.p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
        self.a = 0x0000000000000000000000000000000000000000000000000000000000000000
        self.b = 0x0000000000000000000000000000000000000000000000000000000000000007
        self.Gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
        self.Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
        self.n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
        self.h = 0x1

        subgroup = SubGroup(self.p, (self.Gx, self.Gy), self.n, self.h)
        self.curve = Curve(self.a, self.b, subgroup, name="CustomCurve")

        self.cinit = 0
        self.d = self.privkey_gen()
        self.P = self.curve.g
        self.Q = self.d * self.P

        self.Max_Sec = special_random(getrandbits(32))

    def sec_real_bits(self,bits: int) -> int:
        if bits % 32 != 0:
            raise ValueError("Bit length must be a multiple of 32")   
        exp = bits // 32
        x = self.Max_Sec.get_num() ** exp
        cyc_exhausted = 0
        while x.bit_length() != bits:
            x = self.Max_Sec.get_num() ** exp
            cyc_exhausted += 1
        return (x, cyc_exhausted)  
    
    @staticmethod
    def real_bits(bits) -> int:
        x = getrandbits(bits)
        while x.bit_length() != bits:
            x = getrandbits(bits)
        return x

    @staticmethod
    def supreme_RNG(seed: int, length: int = 10):
        while True:
            str_seed = str(seed) if len(str(seed)) % 2 == 0 else '0' + str(seed)
            sqn = str(seed**2)
            mid = len(str_seed) >> 1
            start = (len(sqn) >> 1) - mid
            end = (len(sqn) >> 1) + mid   
            yield sqn[start : end].zfill(length)
            seed = int(sqn[start : end])  
    
    def restart_level(self):
        print("S T A R T I N G  R O U T I N E . . .\n")

        self.Max_Sec = special_random(getrandbits(32))

        self.d = self.privkey_gen()
        self.P = self.curve.g
        self.Q = self.d * self.P
       
    def sign(self, msg: bytes) -> tuple:
        k, n1, n2, cycles = self.full_noncense_gen() # 全くナンセンスですが、日本語では
        
        kG = k * self.P
        r = kG.x % self.n
        k = k % self.n
        Hmsg = sha256()
        Hmsg.update(msg)

        s = ((b2l(Hmsg.digest()) + r * self.d) * pow(k, -1, self.n)) % self.n

        return (r, s, n1, n2, cycles)
    
    def partial_noncense_gen(self,bits: int, sub_bits: int, shift: int) -> int:
        term = self.real_bits(bits)
        _and = self.real_bits(bits - sub_bits)
        equation = term ^ ((term << shift) & _and) 
        return (term,_and,equation)


    def full_noncense_gen(self) -> tuple:
        k_m1 = self.real_bits(24)
        k_m2 = self.real_bits(24) 
        k_m3 = self.real_bits(69) 
        k_m4 = self.real_bits(30) 

        k_, cycle_1 = self.sec_real_bits(32)
        _k, cycle_2 = self.sec_real_bits(32)

        benjamin1, and1, eq1 = self.partial_noncense_gen(32, 16, 16)
        benjamin2, and2, eq2 = self.partial_noncense_gen(32 ,16 ,16)

        const_list = [k_m1, (benjamin1 >> 24 & 0xFF), k_m2, (benjamin1 >> 16 & 0xFF) , k_, (benjamin1 >> 8 & 0xFF), k_m3, (benjamin1 & 0xFF), k_m4, (benjamin2 >> 24 & 0xFFF), _k]
        shift_list = [232, 224, 200, 192, 160, 152, 83, 75, 45, 33, 0]

        n1 = [and1, eq1]
        n2 = [and2, eq2]
        cycles = [cycle_1, cycle_2]

        noncense = 0
        for const, shift in zip(const_list, shift_list):
            noncense += const << shift
        return noncense, n1, n2, cycles   


    def privkey_gen(self) -> int:
        simple_lcg = lambda x: (x * 0xeccd4f4fea74c2b057dafe9c201bae658da461af44b5f04dd6470818429e043d + 0x8aaf15) % self.n

        if not self.cinit:
            RNG_seed = simple_lcg(CORE)
            self.n_gen = self.supreme_RNG(RNG_seed)
            RNG_gen = next(self.n_gen)
            self.cinit += 1
        else:
            RNG_gen = next(self.n_gen)               

        p1 = hex(self.real_bits(108))
        p2 = hex(self.real_bits(107))[2:]

        priv_key = p1 + RNG_gen[:5] + p2 + RNG_gen[5:]

        return int(priv_key, 16)
    
    def gen_encrypted_flag(self) -> tuple:
        sha2 = sha256()
        sha2.update(str(self.d).encode('ascii'))
        key = sha2.digest()[:16]
        iv = os.urandom(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(FLAG, 16))
        return (ciphertext.hex(), iv.hex())
            
    def _dead_coin_params(self) -> tuple:
        base = 2
        speed = getrandbits(128)
        feedbacker_parry = int(next(self.n_gen))
        style_bonus = feedbacker_parry ^ (feedbacker_parry >> 5)
        power = pow(base, style_bonus, speed)
        return (power, speed, feedbacker_parry)
    
    def deadcoin_verification(self, tries):

        if tries < 3:
            print(f"Successfully perform a {"\33[33m"}deadcoin{"\33[0m"} and perform a {"\33[34m"}feedbacker{"\33[0m"} parry for getting {"\33[1;91m"}BLOOD{"\33[0m"} to survive.\n")
            power, speed, feedbacker_parry = self._dead_coin_params()
            print(f"Calculated power and speed for the number - {tries+1} deadcoin: {power, speed}")
            try:
                action_code = int(input("Action code: "))
                if action_code == feedbacker_parry:
                    blood = self.Max_Sec.get_num()
                    print(f"[+ FISTFUL OF DOLLAR]")
                    print(f"Here's some {"\33[1;91m"}BLOOD{"\33[0m"} - ID: {blood}")
                    return True
                else:
                    print("Missed.")
            except:
                print("Invalid action code")
        else:
            print("You're done.")
        return False


class _1000_THR_EARTHMOVER:
    def __init__(self):
        self.Boss = _1000_THR_Signing_System()

    def get_encrypted_flag(self):
        ciphertext, iv = self.Boss.gen_encrypted_flag()   
        return {"ciphertext": ciphertext,"iv": iv}      
    
    def perform_deadcoin(self, tries):
        return self.Boss.deadcoin_verification(tries)

    def call_the_signer(self):
        msg = input("What do you wish to speak? ").encode()
        r, s, n1, n2, cycles = self.Boss.sign(msg)
        return {"r": r, "s": s, "nonce_gen_consts": [n1, n2], "heat_gen": cycles}

    def level_restart(self):
        self.Boss.restart_level()
    
    def level_quit(self):
        sys.exit()
    
   
def main():
    LEVEL = _1000_THR_EARTHMOVER()
    tries = 0
    title_drop()

    V1 = HP(100,100, "V1", HP.color_red)

    while True:
        try:
            menu_box()
            print(f'\n{V1}')
            move = loads(input("\nExpecting Routine in JSON format: "))

            if "event" not in move:
                print({"Error": "Unrecognised event"})
                continue

            v1_action = move["event"]

            survive = V1.check(v1_action)
            if not survive:
                death_message()
                break

            if v1_action == "get_encrypted_flag":
                print(LEVEL.get_encrypted_flag())
                V1.update(V1.current_health-50)

            elif v1_action == "perform_deadcoin":
                verify = LEVEL.perform_deadcoin(tries)
                tries += 1
                if verify:
                    V1.update(V1.current_health+20)

            elif v1_action == "call_the_signer":
                print(LEVEL.call_the_signer())
                V1.update(V1.current_health-20)

            elif v1_action == "level_restart":
                LEVEL.level_restart()
                V1.update(100)

            elif v1_action == "level_quit":
                LEVEL.level_quit()

            else:
                pass

        except Exception:
            print({"Error": "Unrecognised V1 action"})

        
if __name__ == "__main__":
    main()

```


#### Decor.py
```python 
# Place for the brainrot

class HP:

    bars = 20
    remaining_health_symbol = "█"
    lost_health_symbol = "░"

    color_green = "\033[92m"
    color_yellow = "\33[33m"
    color_red = "\033[91m"
    color_default = "\033[0m"


    def __init__(self, max_health, current_health, name, health_color):
        self.max_health = max_health
        self.current_health = current_health
        self.remaining_health_bars = round(self.current_health / self.max_health * HP.bars)
        self.lost_health_bars = HP.bars - self.remaining_health_bars
        self.health_color = health_color
        self.name = name

    def update(self, current):
        self.current_health = current
        self.remaining_health_bars = round(self.current_health / self.max_health * HP.bars)
        self.lost_health_bars = HP.bars - self.remaining_health_bars
    
    def check(self, move):
        move_cost_dict = {"get_encrypted_flag": 50, "perform_deadcoin" : 0, "call_the_signer" : 20, "level_restart" : 0, "level_quit" : 0}
        if (self.current_health - move_cost_dict[move]) <= 0 :
            return False
        return True
    
    def __repr__(self):
        return f"Your HP : ❤  {'\33[0;101m'}{self.current_health}{'\33[0m'}"f"{self.health_color}{self.remaining_health_bars * self.remaining_health_symbol}"f"{self.lost_health_bars * self.lost_health_symbol}{HP.color_default}"
    

def title_drop():
        from time import sleep
        title_drop = f'''{"\33[1;91m"}
██╗   ██╗██╗ ██████╗ ██╗     ███████╗███╗   ██╗ ██████╗███████╗        ██╗    ██╗    ███████╗███╗   ██╗ ██████╗ ██████╗ ██████╗ ███████╗                                
██║   ██║██║██╔═══██╗██║     ██╔════╝████╗  ██║██╔════╝██╔════╝       ██╔╝   ██╔╝    ██╔════╝████╗  ██║██╔════╝██╔═══██╗██╔══██╗██╔════╝                                
██║   ██║██║██║   ██║██║     █████╗  ██╔██╗ ██║██║     █████╗        ██╔╝   ██╔╝     █████╗  ██╔██╗ ██║██║     ██║   ██║██████╔╝█████╗                                  
╚██╗ ██╔╝██║██║   ██║██║     ██╔══╝  ██║╚██╗██║██║     ██╔══╝       ██╔╝   ██╔╝      ██╔══╝  ██║╚██╗██║██║     ██║   ██║██╔══██╗██╔══╝                                  
 ╚████╔╝ ██║╚██████╔╝███████╗███████╗██║ ╚████║╚██████╗███████╗    ██╔╝   ██╔╝       ███████╗██║ ╚████║╚██████╗╚██████╔╝██║  ██║███████╗                                
  ╚═══╝  ╚═╝ ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═══╝ ╚═════╝╚══════╝    ╚═╝    ╚═╝        ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝                                
                                                                                                                                                                        
         ██╗     ██╗██╗  ██╗███████╗    ██████╗ ██████╗ ███╗   ██╗ ██████╗ ███████╗    ████████╗ ██████╗     ██╗  ██╗███████╗ █████╗ ██╗   ██╗███████╗███╗   ██╗        
         ██║     ██║██║ ██╔╝██╔════╝    ██╔══██╗██╔══██╗████╗  ██║██╔════╝ ██╔════╝    ╚══██╔══╝██╔═══██╗    ██║  ██║██╔════╝██╔══██╗██║   ██║██╔════╝████╗  ██║        
         ██║     ██║█████╔╝ █████╗      ██████╔╝██████╔╝██╔██╗ ██║██║  ███╗███████╗       ██║   ██║   ██║    ███████║█████╗  ███████║██║   ██║█████╗  ██╔██╗ ██║        
         ██║     ██║██╔═██╗ ██╔══╝      ██╔═══╝ ██╔══██╗██║╚██╗██║██║   ██║╚════██║       ██║   ██║   ██║    ██╔══██║██╔══╝  ██╔══██║╚██╗ ██╔╝██╔══╝  ██║╚██╗██║        
██╗██╗██╗███████╗██║██║  ██╗███████╗    ██║     ██║  ██║██║ ╚████║╚██████╔╝███████║       ██║   ╚██████╔╝    ██║  ██║███████╗██║  ██║ ╚████╔╝ ███████╗██║ ╚████║        
╚═╝╚═╝╚═╝╚══════╝╚═╝╚═╝  ╚═╝╚══════╝    ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚══════╝       ╚═╝    ╚═════╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═══╝                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 
{"\33[0m"}'''
        print(title_drop)
        sleep(1.25)
        print("S T A R T I N G  R O U T I N E . . .\n")
        sleep(1)
        print(f'{"\33[1;91m"}WARNING: INTRUDER DETECTED')
        sleep(0.25)
        print(f'-- LIFESTEAL ENABLED --{"\33[0m"}')
        sleep(1)
        
def menu_box():
        rainbow_colors = ["\33[91m", "\33[33m", "\33[92m","\33[34m", "\33[36m", "\33[95m"]
        text = "[+ FISTFUL OF DOLLAR]"
        italy = '\x1B[3m'
        r_c = "\33[0m"

        colored_text = ''.join(f"{rainbow_colors[i % len(rainbow_colors)]}{italy}{char}{r_c}" for i, char in enumerate(text))

        l_pre = "║ 2 - perform_deadcoin << "
        l_suf = "║"
        width = 54 
        text_width = width - len(l_pre) - len(l_suf)
        padd = text_width - len(text)
        res = colored_text + ' ' * padd

        box = f"""
╔════════════════════════════════════════════════════╗
║ 1 - get_encrypted_flag                             ║
{l_pre}{res}{l_suf}
║ 3 - call_the_signer                                ║
║ 4 - level_restart                                  ║
║ 5 - level_quit                                     ║
╚════════════════════════════════════════════════════╝
        """

        print(box)



def death_message():
        print('''

▗▖  ▗▖▗▄▖ ▗▖ ▗▖     ▗▄▖ ▗▄▄▖ ▗▄▄▄▖    ▗▄▄▄  ▗▄▄▄▖ ▗▄▖ ▗▄▄▄  
 ▝▚▞▘▐▌ ▐▌▐▌ ▐▌    ▐▌ ▐▌▐▌ ▐▌▐▌       ▐▌  █ ▐▌   ▐▌ ▐▌▐▌  █ 
  ▐▌ ▐▌ ▐▌▐▌ ▐▌    ▐▛▀▜▌▐▛▀▚▖▐▛▀▀▘    ▐▌  █ ▐▛▀▀▘▐▛▀▜▌▐▌  █ 
  ▐▌ ▝▚▄▞▘▝▚▄▞▘    ▐▌ ▐▌▐▌ ▐▌▐▙▄▄▖    ▐▙▄▄▀ ▐▙▄▄▖▐▌ ▐▌▐▙▄▄▀ 
                                                            

          ⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣤⣤⠴⠶⠶⠶⠶⠶⠶⠶⠶⢤⣤⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀
          ⠀⠀⠀⠀⢀⣤⠶⠛⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠛⠶⣤⡀⠀⠀⠀⠀⠀
          ⠀⠀⢀⡴⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠛⢷⡄⠀⠀⠀
          ⠀⣰⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⣦⠀⠀
          ⢰⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⣧⠀
          ⣿⠀⠀⣤⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⡄⠀⢹⡄
          ⡏⠀⢰⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⠀⢸⡇
          ⣿⠀⠘⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡟⠀⢸⡇
          ⢹⡆⠀⢹⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⠃⠀⣾⠀
          ⠈⢷⡀⢸⡇⠀⢀⣠⣤⣶⣶⣶⣤⡀⠀⠀⠀⠀⠀⢀⣠⣶⣶⣶⣶⣤⣄⠀⠀⣿⠀⣼⠃⠀
          ⠀⠈⢷⣼⠃⠀⣿⣿⣿⣿⣿⣿⣿⣿⡄⠀⠀⠀⠀⣾⣿⣿⣿⣿⣿⣿⣿⡇⠀⢸⡾⠃⠀⠀
          ⠀⠀⠈⣿⠀⠀⢿⣿⣿⣿⣿⣿⣿⣿⠁⠀⠀⠀⠀⢹⣿⣿⣿⣿⣿⣿⣿⠃⠀⢸⡇⠀⠀⠀
          ⠀⠀⠀⣿⠀⠀⠘⢿⣿⣿⣿⣿⡿⠃⠀⢠⠀⣄⠀⠀⠙⢿⣿⣿⣿⡿⠏⠀⠀⢘⡇⠀⠀⠀
          ⠀⠀⠀⢻⡄⠀⠀⠀⠈⠉⠉⠀⠀⠀⣴⣿⠀⣿⣷⠀⠀⠀⠀⠉⠁⠀⠀⠀⠀⢸⡇⠀⠀⠀
          ⠀⠀⠀⠈⠻⣄⡀⠀⠀⠀⠀⠀⠀⢠⣿⣿⠀⣿⣿⣇⠀⠀⠀⠀⠀⠀⠀⢀⣴⠟⠀⠀⠀⠀
          ⠀⠀⠀⠀⠀⠘⣟⠳⣦⡀⠀⠀⠀⠸⣿⡿⠀⢻⣿⡟⠀⠀⠀⠀⣤⡾⢻⡏⠁⠀⠀⠀⠀⠀
          ⠀⠀⠀⠀⠀⠀⢻⡄⢻⠻⣆⠀⠀⠀⠈⠀⠀⠀⠈⠀⠀⠀⢀⡾⢻⠁⢸⠁⠀⠀⠀⠀⠀⠀
          ⠀⠀⠀⠀⠀⠀⢸⡇⠀⡆⢹⠒⡦⢤⠤⡤⢤⢤⡤⣤⠤⡔⡿⢁⡇⠀⡿⠀⠀⠀⠀⠀⠀⠀
          ⠀⠀⠀⠀⠀⠀⠘⡇⠀⢣⢸⠦⣧⣼⣀⡇⢸⢀⣇⣸⣠⡷⢇⢸⠀⠀⡇⠀⠀⠀⠀⠀⠀⠀
          ⠀⠀⠀⠀⠀⠀⠀⣷⠀⠈⠺⣄⣇⢸⠉⡏⢹⠉⡏⢹⢀⣧⠾⠋⠀⢠⡇⠀⠀⠀⠀⠀⠀⠀
          ⠀⠀⠀⠀⠀⠀⠀⠻⣆⠀⠀⠀⠈⠉⠙⠓⠚⠚⠋⠉⠁⠀⠀⠀⢀⡾⠁⠀⠀⠀⠀⠀⠀⠀
          ⠀⠀⠀⠀⠀⠀⠀⠀⠙⢷⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⡴⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀
          ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⠳⠶⠦⣤⣤⣤⡤⠶⠞⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
''')
```

### RMT.py
```python
class R_MT19937_32bit:
    def __init__(self, seed=0):
        self.f = 1812433253
        (self.w, self.n, self.m, self.r) = (32, 624, 397, 31)
        (self.u, self.s, self.t, self.l)= (11, 7, 15, 18)
        (self.a, self.b, self.c) = (0x9908b0df, 0x9d2c5680, 0xefc60000)
        (self.lower, self.upper, self.d) = (0x7fffffff, 0x80000000, 0xffffffff)
        self.MT = [0 for i in range(self.n)]
        self.seedMT(seed)

    def seedMT(self, seed):
        num = seed
        self.index = self.n
        for _ in range(0,51):
            num = 69069 * num + 1
        g_prev = num
        for i in range(self.n):
            g = 69069 * g_prev + 1
            self.MT[i] = g & self.d
            g_prev = g
        
        return self.MT

    def twist(self):
        for i in range(0, self.n):
            x = (self.MT[i] & self.upper) + (self.MT[(i + 1) % self.n] & self.lower)
            xA = x >> 1
            if (x % 2) != 0:
                xA = xA ^ self.a
            self.MT[i] = self.MT[(i + self.m) % self.n] ^ xA
        self.index = 0

    def get_num(self):
        if self.index >= self.n:
            self.twist()
        y = self.MT[self.index]
        y = y ^ ((y >> self.u) & self.d)
        y = y ^ ((y << self.s) & self.b)
        y = y ^ ((y << self.t) & self.c)
        y = y ^ (y >> self.l)
        self.index += 1
        return y & ((1 << self.w) - 1)
```

From the above files we know
- There is ECDSA happening using secp256k1 curve.
- The Private Key is generated using a custom prng function called `supreme_PRNG()`.
- The Nonce is generated using `full_noncense_gen()` which internally makes calls to the `RMT` via `sec_real_bits()` and `partial_noncense_gen()`.
- There is a small `perform_deadcoin()` mini-game happening where you solve a DLP problem.
- There is a interface through which we can send JSON encoded "routines" to perform 5 different actions:	
	- `get_encrypted_flag` -> gives you the AES-CBC encrypted ciphertext and IV.
	- `perform_deadcoin` -> gives you the chance to heal your HP bar if you solve a DLP problem.
	- `call_the_signer` -> signs any arbitrary message and returns `r` and `s` values along with `nonce_gen_consts` and `heat_gen`.
	- `level_restart` -> lets you restart the level and regenerates the Private Key and seed for the RMT.
	- `level_quit` -> well duh, let's you quit the connection.
- `RMT` which seems to have a different seed initialisation function when compared to python's MT.

### Analysis

From quite literally glancing through the signing system, we can tell that the nonce generation and private key generation has some inherent bias and moreover the chunks are non-continuous, so we can model the problem as a `EHNP` instance and perform LLL to solve it.

But there seems to be a catch
```python
            elif v1_action == "call_the_signer":
                print(LEVEL.call_the_signer())
                V1.update(V1.current_health-20)
```
The HP will deteriorate by `-20` for every message we sign thus limiting us to two signatures before we can query for the encrypted flag.

Now to approach the challenge, we need enough HP to sign at least 5 messages before we can find the private key using LLL.

#### PRNGS
Let's analyse each of the PRNGS:
1.  `RMT`
	- The only difference between python's MT and RMT is the `seedMT()` function or more popularly called as Ripley's Seeding. This version of MT is used in the programming language R.
	- It uses a 32 bit seed and uses the same 32 bit parameters of a standard MT.
	- `seedMT()` tries to grow a value and update the internal state of the MT.
        ```python
          def seedMT(self, seed):
        num = seed
        self.index = self.n
        for _ in range(0,51):
            num = 69069 * num + 1
        g_prev = num
        for i in range(self.n):
            g = 69069 * g_prev + 1
            self.MT[i] = g & self.d
            g_prev = g
        
        return self.MT
        ```
	- MT is reversible with z3 Solver and as for `seedMT()` it can also be easily modelled in z3.

2. `supreme_RNG()`
	- It uses the Middle Square Method to generate the next number.
	- MSM is not cryptographically secure as the generated values will decay and remain stagnant producing a very short cycle.

There is also a simple LCG which is used only once per restart as:
```python
    def privkey_gen(self) -> int:
        simple_lcg = lambda x: (x * 0xeccd4f4fea74c2b057dafe9c201bae658da461af44b5f04dd6470818429e043d + 0x8aaf15) % self.n

        if not self.cinit:
            RNG_seed = simple_lcg(CORE)
            self.n_gen = self.supreme_RNG(RNG_seed)
            RNG_gen = next(self.n_gen)
            self.cinit += 1
        else:
            RNG_gen = next(self.n_gen) 

            ... 
```

```python
        ...
        self.cinit = 0
        self.d = self.privkey_gen()
        ...
```

it is only called when  `self.cinit` is 0.

#### Other important funcs

- `perform_deadcoin()` as we have previously established, let's you play the mini-game where you solve a DLP problem in-exchange for a 32 bit value from the `RMT` but there is a hard limit of only being able to play this thrice.
- Now, after analysing `deadcoin_verification()` and `_dead_coin_params()`, the mini-game seems to derive it's exponent from `supreme_RNG()`  which takes its seed from the simple LCG.
- The simple LCG *always* produces the value `1569250000` as it is *always* seeded with `CORE` and is run only once per level.
- This value specifically decays to 0 at the 375 cycle.

Now let's look at `full_noncense_gen()`
- It introduces `k_m1, k_m2, k_m3, k_m4` which are cryptographically secure but add bias and `k_ and _k` which are generated from `RMT` along with `benjamin1, benjamin2`
- `k_ and _k` are both 32 bit values and `benjamin1 and benjamin2` are 16 bit values.
- `benjamin1` is split into chunks of one byte and is made to be every alternate chunk in the nonce except for the last alternate chunk where 12 lsb of `benjamin2` is used.
- Both the benjamin values are generated by `partial_noncense_gen()` and are of the form: $$y \gets b \ \oplus (b \ll s) \ \wedge \ a$$ where $b \in [0,2^{32}]$ and $y,a \in [0,2^{16}]$
- The `full_noncense_gen()` also returns `n1` and `n2` values which are later given as `nonce_gen_consts` which are `equation, _and` value from `partial_noncense_gen`.
- It also returns `cycles` which are later given out as `heat_gen`  which denotes the number of calls to `RMT` before getting the right bit length.

In `decor.py` we can also see that there are no checks on going beyond 100 HP, so we can try to over-heal and get more signatures.

From all the above information, we can formulate our exploit.

- Restart the level 375 times.
- Now the exponent in `deadcoin_verification()` will be 0 so you can easily pass this check three times and get 3 `RMT` values and reconstruct the seed using z3 Solver. This also sets your HP to 160.
- Now we sign any arbitrary message five times (our maximum limit) whilst simultaneously accounting for the number of `RMT` calls from the `heat_gen`. We can also rebuild both benjamin values using z3 Solver.
- As there is some bias introduced in the private key, we assign it to the var `xbar` and also calculate `kbar` with the appropriate shifts.
- We can now construct $\pi\_{i}$ and $\nu\_{i}$ from the below equation: $$d \ = \ \bar{d} \ +\ \sum\_{j=1}^{m} 2^{\pi\_{j}}d_{j} \ \ , \ \ 0 \leq d_{j} \leq \ 2^{\nu\_{j}}$$ using the appropriate shifts and bit lengths
- Similarly we can construct $\lambda\_{i,j}$ and $\mu\_{i,j}\$ from the below equation: $$k_{i} = \bar{k_{i}} +\sum\_{j=1}^{l_{i}}2^{\lambda\_{i,j}}k_{i,j} \ \ , \ \ 0 \leq k_{i,j} < 2^{\mu\_{i,j}}$$ using the appropriate shifts and bit lengths given in the code.
- We can now convert this into a CVP instance and use LLL to solve it to find the private key.
  The basis: $$B = \begin{bmatrix}n \cdot I_{x}\\\ A&X\\\ R&&K \end{bmatrix}$$

   Each of the internal matrices can be referred from this amazing [paper](https://eprint.iacr.org/2023/032.pdf) by [Joseph Surin](https://jsur.in/) (EHNP part).
  - In essence let $$x = (r_{1},\dots, r\_{x},d\_{1},\dots,d\_{m},d\_{1,1}\dots,d\_{x,l_{1}},\dots,d\_{x,l_{x}})$$ We would have, $$xB = u$$
	  $$u =( \beta_{1} - \alpha_{1}\bar{d},\dots,\beta_{x} - \alpha_{x}\bar{d}, \frac{d_{1}\delta}{2^{\nu_{1}}},\dots,\frac{d_{m}\delta}{2^{\nu_{m}}}, \frac{k_{1,1}\delta}{2^{\mu_{1,1}}},\dots,\frac{k_{1,l_{1}}\delta}{2^{\mu_{1,l_{1}}}},\dots,\frac{k_{x,1}\delta}{2^{\mu_{x,1}}},\dots,\frac{k_{x,l_{x}}\delta}{2^{\mu_{x,l_{x}}}})$$
	  So we can let
	  $$w = (\beta_{1} - \alpha_{1}\bar{d},\dots,\beta_{x} - \alpha_{x}\bar{d}, \frac{\delta}{2},\dots,\frac{\delta}{2}, \frac{\delta}{2},\dots,\frac{\delta}{2},\dots,\frac{\delta}{2},\dots,\frac{\delta}{2})$$
	  as $w$ is close to the lattice vector $u$, therefore solving a CVP instance with $w$ as the target vector may give us lattice vector $u$ which encodes the secret chunks $d_{j}$ in the $(x+1)^{st}$ to the $(x+m)^{th}$ entries.
	  `Note: x and d are interchanged from the paper, d here is the private key and x here is the number of equations.` 
- Once the private key is found, we can now send `{"event" : "get_encrypted_flag"}` and can perform AES-CBC decryption on it, you will be left with 10 HP and you get the flag.
### Exploit

#### Solve.sage

```python
from pwn import *
from z3 import *
from sage.all import *
import json
import ast
from tqdm import trange
from hashlib import sha256
from RMT import R_MT19937_32bit as R_mt

class BreakerRipley32:
    """
    Z3 solver for 32-bit Mersenne Twister with Ripley seeding
    """
    def __init__(self):
        (self.w, self.n, self.m, self.r) = (32, 624, 397, 31)
        self.a = 0x9908B0DF
        (self.u, self.d) = (11, 0xFFFFFFFF)
        (self.s, self.b) = (7, 0x9D2C5680)
        (self.t, self.c) = (15, 0xEFC60000)
        self.l = 18
        self.num_bits = 32
        self.lower_mask = (1 << self.r) - 1
        self.upper_mask = 0x80000000 

    def tamper_state(self, y):
        y = y ^^ (LShR(y, self.u) & self.d)
        y = y ^^ ((y << self.s) & self.b)
        y = y ^^ ((y << self.t) & self.c)
        y = y ^^ LShR(y, self.l)
        return y

    def untamper(self, num):
        def undo_right_shift_xor_and(y, shift, mask):
            res = y
            for _ in range(5): 
                res = y ^^ ((res >> shift) & mask)
            return res

        def undo_left_shift_xor_and(y, shift, mask):
            res = y
            for _ in range(5):
                res = y ^^ ((res << shift) & mask)
            return res

        y = undo_right_shift_xor_and(num, self.l, 0xFFFFFFFF)
        y = undo_left_shift_xor_and(y, self.t, self.c)
        y = undo_left_shift_xor_and(y, self.s, self.b)
        y = undo_right_shift_xor_and(y, self.u, self.d)
        return y

    def twist_state(self, MT):
        n, m, a = self.n, self.m, self.a
        lower_mask, upper_mask = self.lower_mask, self.upper_mask
        new_MT = [BitVec(f"MT_twisted_{i}", 32) for i in range(n)]
        for i in range(n):
            x = (MT[i] & upper_mask) + (MT[(i + 1) % n] & lower_mask)
            xA = LShR(x, 1)
            xA = If(x & 1 == 1, xA ^^ a, xA)
            new_MT[i] = simplify(MT[(i + m) % n] ^^ xA)
        return new_MT

    def get_seed_mt(self, outputs):
        n = self.n
        SEED = BitVec('seed', 32)
        MT = [BitVec(f"MT_init_{i}", 32) for i in range(n)]

        # Ripley seeding (sow and grow seeds)
        num = SEED
        for _ in range(51):
            num = 69069 * num + 1 
        g_prev = num
        constraints = []
        for i in range(n):
            g = 69069 * g_prev + 1
            constraints.append(MT[i] == (g & 0xFFFFFFFF))
            g_prev = g

        MT_twisted = self.twist_state(MT)

        S = Solver()
        S.add(constraints)
        for idx, value in outputs:
            S.add(self.tamper_state(MT_twisted[idx]) == value)

        # Solve for the seed
        if S.check() == sat:
            model = S.model()
            return model[SEED].as_long()
        else:
            return None
            
# Quick and reliable
load("https://raw.githubusercontent.com/josephsurin/lattice-based-cryptanalysis/refs/heads/main/lbc_toolkit/common/babai_cvp.sage")
load("https://raw.githubusercontent.com/josephsurin/lattice-based-cryptanalysis/refs/heads/main/lbc_toolkit/problems/hidden_number_problem.sage")
load("https://raw.githubusercontent.com/josephsurin/lattice-based-cryptanalysis/refs/heads/main/lbc_toolkit/attacks/ecdsa_key_disclosure.sage")

def json_sender(msg):
    json_msg = json.dumps(msg).encode()
    io.sendline(json_msg)

def RNG_decayer():
    print(f"[{neutral("*")}] Restarting enough times to exploit MSM...")
    for _ in trange(375):
        io.recvuntil(routine_pass)
        json_sender(possible_events[3])

def deadcoin():
    print(f"[{neutral("*")}] Deadcoining for RMT values...")
    RMT_vals = []
    for i in range(3):
        io.recvuntil(routine_pass)
        json_sender(possible_events[1])
        io.recvuntil(b'code: ')
        json_sender(int(0))
        io.recvuntil(b'ID: ')
        RMT_vals.append((i, int(io.recvline().decode())))
    return RMT_vals

def partial_nonce_breaker(_and, equation):
    term = BitVec('term', 32)
    res = term ^^ ((term << 16) & _and)
    S = Solver()
    S.add(res == equation)
    if S.check() == sat:
        model = S.model()
        return model[term].as_long()
    else:
        return None

def decrypt_flag(d,ciphertext,iv) -> tuple:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
    
    ciphertext=bytes.fromhex(ciphertext)
    iv = bytes.fromhex(iv)
    sha2 = sha256()
    sha2.update(str(d).encode('ascii'))
    key = sha2.digest()[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext.decode()
    
HOST = 'localhost'
PORT = 5000

io = remote(HOST, PORT)

# Idk man I like pretty printing
neutral = lambda text: ''.join(f"{"\033[92m"}{char}{"\033[0m"}" for _, char in enumerate(text))
happy = lambda text: ''.join(f"{"\033[34m"}{char}{"\033[0m"}" for _, char in enumerate(text))

possible_events = [
    {'event': 'get_encrypted_flag'},
    {'event': 'perform_deadcoin'},
    {'event': 'call_the_signer'},
    {'event': 'level_restart'},
    {'event': 'level_quit'}
]

routine_pass = b'JSON format: '

RNG_decayer()
outputs = deadcoin()
print(outputs)
breaker = BreakerRipley32()
recovered_seed = breaker.get_seed_mt(outputs)
print("Recovered seed:", recovered_seed)

MT = R_mt(recovered_seed)
for _ in range(3):
    MT.get_num()

R = []
S = []
B = []
p_Ki = []

msg = "hello world".encode()

cnt = 5
for _ in range(cnt):
    io.recvuntil(routine_pass)
    json_sender(possible_events[2])
    io.recvuntil(b'speak? ')
    io.sendline(msg)
    sign_res = ast.literal_eval(io.recvline().decode())
    R.append(sign_res['r'])
    S.append(sign_res['s'])
    n_gen_const = sign_res['nonce_gen_consts']
    cycles = sign_res['heat_gen']


    ki = []
    for i in cycles:
        for s in range(i):
            MT.get_num()
        pk = MT.get_num()
        ki.append(pk)
    p_Ki.append(ki)

    

    b_buf = []
    for i in range(2):
        _and, equation = n_gen_const[i]
        b = partial_nonce_breaker(_and, equation)
        b_buf.append(b)
    B.append(b_buf)


Kbar = []


for b_i, k_i in zip(B,p_Ki):
    b1,b2 = b_i
    k1,k2 = k_i
    
    Ki = 2^224*(b1 >> 24 & 0xFF) + 2^192*(b1 >> 16 & 0xFF) + 2^160*k1 + 2^152*(b1 >> 8 & 0xFF) + 2^75*(b1 & 0xFF) + 2^33*(b2 >> 24 & 0xFFF) + k2
    Kbar.append(Ki)


xbar = 0
n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
Pi = [148,21] # associared with d
Nu =[108,107] # associated with d
zi = sha256()
zi.update(msg)
Z = [int(zi.hexdigest(),16) for _ in range(cnt)]
Mu = [[24,24,69,30]  for _ in range(cnt)]
lambdha = [[232,200,83,45] for _ in range(cnt)]

d = ecdsa_key_disclosure(xbar, n, Z, R, S, Kbar, Pi, Nu, lambdha, Mu)

io.recvuntil(routine_pass)
json_sender(possible_events[0])

rec = ast.literal_eval(io.recvline().decode())

ciphertext = rec["ciphertext"]
iv = rec["iv"]

print(f'[{happy("!")}] FLAG: {decrypt_flag(d, ciphertext, iv)}')

```

The flag is `bi0sCTF{p4rry_7h15_y0u_f1l7hy_w4r_m4ch1n3}`


### Aftermath

It looked like the 32 bit seed could be bruteforced and could be solved in an unintended way skipping z3 entirely for the solve ([Dorian](https://github.com/dorian-k) managed to solve that way) 💀 and Benjamin values not being necessary for the LLL part. 
