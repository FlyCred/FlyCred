# FlyCred: Conditional Anonymous Credentials

This is the code repository accompanying our paper "FlyCred: Conditional Anonymous Credentials".

The code uses the Charm library and Python and builds upon the code of [FEASE] https://github.com/Usenix2024/FEASE (2024). We provide the implementation of the following schemes:

1. AAC (Fig. 4)
2. AbeSWET (Fig. 5)
3. FlyCred (Fig. 6)

All schemes are implemented using Type-III pairing groups. 

We test the performance of the schemes on three elliptic curves, including MNT159 (80-bit security), MNT201 (90-bit security), and BN254 (100-bit security), using Charm 0.50, PBC (Pairing-Based Cryptography) library, and Python 3.10 on Ubuntu Kylin 16.04.

PBC can be installed directly from [this] (https://crypto.stanford.edu/pbc/) page. 

Charm 0.50 can be installed directly from [this] (https://github.com/JHUISI/charm) page, or by running

```sh
pip install -r requirements.txt
```
Once you have Charm, run
```sh
make && pip install . && python samples/run_cp_schemes.py
```
## References
1. Meng L, Chen L, Tian Y, et al. FEASE: Fast and Expressive Asymmetric Searchable Encryption[J]. IACR Cryptol. ePrint Arch., 2024, 2024: 54.
