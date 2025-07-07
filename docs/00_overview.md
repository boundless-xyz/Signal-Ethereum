# The Signal: Ethereum — A Formal Analysis

This documentation provides the complete formal analysis for the TSEth consensus core. It is split into two primary parts, which are best read in order:

1.  **[Formalization of the Consensus Algorithm](./01_consensus_algorithm.md)**
    * This document formally defines the **Atomic Finalization** algorithm, its data structures, and proves its compatibility with the standard Casper FFG.

2.  **[Safety Analysis of Balance Drift](./02_balance_drift.md)**
    * This document provides the detailed mathematical derivation of the safety margin (`δ`) required to account for validator balance drift when verifying proofs from a historical state.

---

## **Introduction and Framework**

TSEth is a zkVM-friendly implementation of Casper FFG, designed around a simplified *Atomic Finalization Algorithm*. The core of this approach is to verify a state transition from a given consensus state—derived from a previously finalized checkpoint—to a new, target consensus state. This verification is performed within a zkVM guest program, allowing a full node to generate a succinct proof of finality.

This process is initiated by providing the guest program with a consensus state containing a finalized checkpoint. The root of this checkpoint serves as a **root of trust**, allowing any data from the corresponding Beacon state (like the validator registry) to be proven via Merkle proofs and used as trusted inputs for the guest.

To prove this state transition, the guest program also requires information not contained in the trusted state. The prover must supply a **witness** that includes the sequence of supermajority links leading to the new finality, as well as auxiliary data like future RANDAO values for committee calculation.

The fundamental challenge is that the guest program must use the validator balances from the trusted state at $epoch_0$ to validate these attestations. This creates a discrepancy with the official Ethereum protocol, which uses the effective balances from the epoch in which the justification is applied. This **"balance drift"** grows with the number of epochs between the trusted checkpoint and the new target.

This body of work provides a formal safety analysis for this "balance drift". We derive a conservative upper bound for this drift and use it to define a **safety margin ($\delta$)**. By requiring the attesting balance in our guest program to exceed the standard two-thirds supermajority by this margin, we can guarantee the safety of the finalized checkpoint, even without access to the most recent state.