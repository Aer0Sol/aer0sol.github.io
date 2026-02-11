---
date: 2026-02-02
title: "Eschaton 2026 Crypto - Noisy Channels"
toc: true
description: "Writeup for the Noisy Channels challenge from Eschaton CTF 2026."
math: true
cover: /images/covers/noisy_channel_top.jpg
tags: 
- LWE
- Lattice
- Side-Channel
categories: Writeup
---


## Challenge Description
`Nil`

### Handout
[Intercept.json](https://gist.github.com/Aer0Sol/0efc92c4748f61725f1bf36f448a22fb)

## Analysis
- We are given `intercept.json` with the following keys: modulus, dimension, public_matrix, ciphertext, timing_ns, power_trace and encrypted flag.
- Due to the absence of a source file which implies we need to guess the cryptosystem, I started searching about NewHope, given that specific modulus
- Well.. I found nothing of high correlation so I just assumed this to be a LWE instance with some quirk.
- First thing we can do is figure out some properties of the timing matrix and the power trace matrix to get some idea about the errors involved.
-  From some observations, we can see the timing_ns distribution form three clusters and the power trace forms two clusters. We can visualise the different clusters as: ![Distributions](distributions.png)
- `len(encrypted_flag)` is 34 which is interesting.
- Since it is a black box which means we have no idea what's exactly happening, we can assume the simpler case where we are working with binary errors, which means: $$A \cdot b + e \equiv S \bmod q \ : \  e \in [0,1]$$ where A is the public matrix and b is the ciphertext matrix.
- Since we have an excess of equations, we can just consider the case where $e = 0$ which boils this challenge into a system of equations and that can be solved by simple Gaussian reduction.

### I have no idea what to title this 💀

We simply can't end the challenge by getting S, we have an encrypted flag matrix for which I had no idea how we can arrive at it. Thankfully Mr. Gemini came up with this amazing line:

```python
s_str = ','.join(map(str, S)).encode()
key = hashlib.sha256(s_str).digest()

full_key = key + key[:2] 

dec = bytes([enc_flag[i] ^ full_key[i] for i in range(34)])
print(f"FLAG: {dec.decode()}")
```

## Solve script

```python
import json
import numpy as np
import hashlib
from sage.all import *

d = json.load(open('intercept.json'))

q = d['modulus']
n = d['dimension']
A = np.array(d['public_matrix'], dtype=np.int64)
b = np.array(d['ciphertext'], dtype=np.int64)
timing = np.array(d['timing_ns'])
power = np.array(d['power_trace'])
enc_flag = bytes(d['encrypted_flag'])

timing_bits = np.array([1 if t > 1210 else 0 for t in timing])
power_bits = np.array([1 if p > 110 else 0 for p in power])
agreed = timing_bits == power_bits
confident_zero = np.where(agreed & (timing_bits == 0))[0]

idx = confident_zero[:200]
A_sub = A[idx].copy()
b_sub = b[idx].copy()

Al = Matrix(GF(q), A_sub)
bl = Matrix(GF(q), list(b_sub))

S = []
for i in range(b_sub.size):
	S.append(Al.augment(bl.T).rref()[i][-1])

s_str = ','.join(map(str, S)).encode()
key = hashlib.sha256(s_str).digest()

full_key = key + key[:2] 

dec = bytes([enc_flag[i] ^ full_key[i] for i in range(34)])
print(f"FLAG: {dec.decode()}")
```

Flag : `esch{t1m1ng_0r4cl3s_4r3_d4ng3r0us}`
