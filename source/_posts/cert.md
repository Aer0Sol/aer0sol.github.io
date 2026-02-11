---
date: 2024-12-10
title: "LakeCTF 2024 Crypto - Cert"
toc: true
description: "Writeup on a LakeCTF'24 crypto challenge"
math: true
cover: /images/covers/cert_top.gif
tags: 
- Fault
- RSA
categories: Writeup
---



## Challenge Description

```
Here is the admin's public key:

N = b678170a2e2faf2a29d6b236a8508c4a27a828c5c9f40ad467768ef60af30eda4e8596e4cbc3919db6d104ea1155025052918fb8fb3ef78510c6ea41f5be60e26103fb0f36a71883a23027f544b08ad35fc328b184e83f8973695e339d75fe4565e90457f051ba327eb14d77d76fc60b8800e5d04d9407561dc708889ee8b001

e = 010001

Forge a signature to authenticate as admin.

Hold on! Let me quickly sign a welcome message for you

nc chall.polygl0ts.ch 9024
```

## Source files

[cert.py](./cert.py) 
[precomputed.py](./precomputed.py) 


## Source Analysis

### precomputed.py

```python
from Crypto.Util.number import bytes_to_long

message = "Sign \"admin\" for flag. Cheers, "
m = 147375778215096992303698953296971440676323238260974337233541805023476001824
N = 128134160623834514804190012838497659744559662971015449992742073261127899204627514400519744946918210411041809618188694716954631963628028483173612071660003564406245581>
e = 65537
signature = 2066100189908203831467740668064384570451707972733136413344205404539358351467797272063760846108596471121604572134007316135429454288237472477734942807611858337>
assert(m == bytes_to_long(message.encode()))
```

### cert.py
```python
from binascii import hexlify, unhexlify
from Crypto.Util.number import bytes_to_long, long_to_bytes
from precomputed import message, signature, N, e
from flag import flag


if __name__ == "__main__":
    print(message + hexlify(long_to_bytes(signature)).decode())
    cert = input(" > ")
    try:
        s = bytes_to_long(unhexlify(cert))
        assert(s < N)
        if pow(s,e,N)==bytes_to_long("admin".encode()):
            print(flag)
        else:
            print("Not admin")
    except:
        print("Not admin")
```

We are given a message m, e, N and a signature in precomputed.py and cert.py checks if the signature of "admin" is sent to the server, if yes, the flag is printed.

Interestingly:
$$m \not\equiv s^e \bmod N$$
It is not clear for which message this is intended for but since nothing else is provided, it is safe to assume that this is most likely a **faulty signature**.

### Theory

In the case without fault:
$$\begin{aligned} m^d &\equiv s \pmod{N}, \\ s^e &\equiv m \pmod{N} \end{aligned}$$In the case of RSA-CRT fault attack:


$$\begin{aligned} &\text{Let's assume faulty signature to be} \ \bar{s}. \\ \\
&\begin{cases} \bar{s}^e = m \pmod{p} \\ \bar{s}^e \neq m \pmod{q} \end{cases} \implies \begin{cases} \bar{s}^e - m = 0 \pmod{p} \\ \bar{s}^e - m \neq 0 \pmod{q} \end{cases} \implies \begin{cases} (\bar{s}^e - m)= kp \\ (\bar{s}^e - m) \not= kq \end{cases} \end{aligned}
$$

This is good for us as we can simply do $gcd(s^e - m, N)$  and that will give us $p$. And with that factorising N becomes trivial.

## Solve script

```python
from math import gcd
from Crypto.Util.number import bytes_to_long as b2l
from pwn import remote

def attack_known_m(n, e, m, s):
    g = gcd(m - pow(s, e, n), n)
    return None if g == 1 else (g, n // g)

def compPayload(p,q):
    phi = (p-1)*(q-1)
    d = pow(e,-1,phi)
    msg = b2l(b'admin')
    payload = pow(msg,d,N)
    return hex(payload)[2:].encode()


HOST = 'chall.polygl0ts.ch'
PORT = 9024

io = remote(HOST,PORT)

m = 147375778215096992303698953296971440676323238260974337233541805023476001824
N = 128134160623834514804190012838497659744559662971015449992742073261127899204627514400519744946918210411041809618188694716954631963628028483173612071660003564406245581>
e = 65537
signature = 2066100189908203831467740668064384570451707972733136413344205404539358351467797272063760846108596471121604572134007316135429454288237472477734942807611858337>

p,q = attack_known_m(N,e,m,signature)
payload = compPayload(p,q)

io.sendlineafter(b" > ", payload)
print(io.recvline().decode())
```
**Flag** : `EPFL{Fau17Y_5igNs_Ar3_al!_y0U_ne3D}`





