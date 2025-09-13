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
