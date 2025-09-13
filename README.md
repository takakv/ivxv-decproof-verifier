# IVXV decryption proof verifier

An independent tool for verifying the ZKPoKs of correct decryption for IVXV.
IVXV is the (code)name of the system currently used in Estonia for online voting.

NB! This tool only verifies the cryptographic proofs.
It does not perform other important audit checks such as verifying:

- that the decryption proofs are consistent with the ballot box,
- the integrity of the proofs and ballot box files,
- the validity of the decrypted results (voter choices),
- that the official final tally corresponds to the decrypted results.

To obtain the proofs, you must submit a written request to the State Electoral Office (info [at] valimised.ee).
Unfortunately, the proofs are not currently published on the [elections website](https://valimised.ee).

Alternatively, if you want to obtain dummy data to test this tool or validate your own,
you can use the [ivxv-dummygen](https://github.com/takakv/ivxv-dummygen) Python tool (also written by me).

Useful links about IVXV:

- [Source code](https://github.com/valimised/ivxv/tree/published/auditor) of the official IVXV auditing application.
- [Documents](https://www.valimised.ee/en/internet-voting/documents-about-internet-voting) about internet voting.
  Most are in Estonian, but some are available in English.
- [Information](https://www.valimised.ee/en/internet-voting/observing-auditing-testing) about observing, auditing and
  testing.

## ZKPoK of correct decryption

IVXV uses the ElGamal cryptosystem with the [P-384](https://neuromancer.sk/std/nist/P-384) curve.
Let $n$ denote the order of the curve, and let $G$ be its base point.

### El Gamal

The ElGamal secret key $x \stackrel{u}{\gets} \lbrace 1, \dots, n - 1\rbrace$ is sampled uniformly at random
and the public key is computed as $H \gets xG$.

- A message (encoded to a point) $M$ is encrypted as
  
  $$\mathsf{Enc}_H(m; r) = (rG, M + rH) \stackrel{\mathsf{def}}{=}(U, V)$$

  where $r \stackrel{u}{\gets} \lbrace 1, \dots, n - 1\rbrace$ is the ephemeral encryption randomness.
- A ciphertext $(U, V)$ is decrypted as

  $$\mathsf{Dec}_x((U, V)) = V - xU = M.$$

To prove that the decryption yields the claimed plaintext, the prover must prove that:

- they know the secret key,
- the claimed plaintext is the result of decrypting the given ciphertext with this key.

Both can be proven with a single proof by using the proof of discrete logarithm equality by
[Chaum and Pedersen](https://link.springer.com/chapter/10.1007/3-540-48071-4_7).

### Chaum-Pedersen protocol

Let $x$ be the secret key and let $G, P$ be group elements.
The Chaum-Pedersen protocol allows the prover to demonstrate knowledge of $x$ such that

$$H = xG \quad\land\quad Q = xP$$

for given group elements $H, Q$.

Let $M'$ denote the claimed decryption result.
If the Chaum-Pedersen transcript is accepting for

- $P = U$,
- $Q = V - M'$,
- the public key $H$ and generator $G$,

then by soundness of the protocol, the prover knows $x$ such that $H = xG$ and $V - M' = xU$.
Since $U = rG$, it follows that

$$V - M' = xU = x(rG) = r(xG) = rH = V - M \implies M = M'.$$

It follows that the ciphertext was:

- decrypted with the secret key corresponding to the public key $H$,
- the claimed decryption result is indeed correct.

The interactive protocol itself is as follows:

1. The prover computes

   $$t \stackrel{u}{\gets} \lbrace 0, \dots, n - 1\rbrace,\quad A \gets tU,\quad B \gets tG$$

   and sends the commitments $A, B$ to the verifier.
   In IVXV, $A$ is called the ‘message commitment’ and $B$ the ‘key commitment’.

2. The verifier samples the challenge $k \stackrel{u}{\gets} \lbrace 0, \dots, n - 1\rbrace$ uniformly at random
   and sends it to the prover.

3. The prover computes the response

   $$s \gets t + kx \pmod{n}$$

   and sends it to the verifier.

The proof transcript is $\bigl((A, B), k, s\bigr)$.

To verify the proof, the verifier must verify that

$$sU = A + k(V - M) \quad\land\quad sG = B + kH.$$

