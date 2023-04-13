# Signature Pre-image Proof of Address

Author: Tan Teik Guan

This project works on using MPC-in-the-head to create zero-knowledge proof of ownership of web3 addresses. Under the hood, we use :
- SPP (Signature Pre-image Proof) - a patent-pending method to make existing classical signatures (ECDSA, etc) quantum-safe. More details at: https://link.springer.com/chapter/10.1007/978-3-030-91356-4_2
- KKW (Katz-Kalesnikov-Wang) - a space-optimized construction of MPC-in-the-head that is the basis for Picnic in Microsoft's PQC submission. More details at: https://eprint.iacr.org/2018/475.pdf
