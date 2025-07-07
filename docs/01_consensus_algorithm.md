# Formalization of the Consensus Algorithm

### **Definition: Consensus State**
Given two checkpoints $f$ and $c$, where $f$ is also called the *finalized checkpoint* and $c$ the *current justified checkpoint*. We call the ordered pair $(f,c)$ a **Consensus State**, when $f$ is a predecessor of $c$.

### **Algorithm: Atomic Finalization**
#### Input:
- A consensus state $(f,c)$.
- A sequence of $k$ supermajority links $\left(c\to b_1,b_1 \to b_2, \dots, b_{k-1} \to b_k \right)$.
#### Procedure:
The algorithm proceeds only if the *final link* in the sequence, $b_{k-1} \to b_k$, satisfies the condition $epoch(b_k) = epoch(b_{k-1}) + 1$. Otherwise, the operation aborts.
#### Output:
- The new consensus state $(b_{k-1}, b_k)$

## Compatibility Analysis with Casper FFG

We argue the compatibility of our Consensus Algorithm with Casper FFG, assuming no 2-finalizations occur. The `finalized_checkpoint` and `current_justified_checkpoint` fields in the Beacon state induce a valid consensus state.

### **Definition: Induced Consensus State**
We call a consensus state $(f,c)$ *induced* by the Beacon state at checkpoint $s$, when $f$ matches the `finalized_checkpoint` field and $c$ matches the `current_justified_checkpoint` field of the Beacon state as referenced by the checkpoint $s$.

### **Theorem 1**
Let $s$ and $t$ be two finalized checkpoints in a view $G$ of Caper FFG, where $s$ is a predecessor of $t$. Let $\mathcal{A}$ be the chain of supermajority links ("attestations") included in the blocks between $s$ and $t$ that causes $t$ to be finalized.
Executing the *Atomic Finalization* algorithm with the consensus state $(f,c)$ induced by $s$ and the chain of supermajority links ("attestations") included in the blocks between $s$ and $t$, will return the consensus state induced by $t$.

#### Proof:
By definition, for Casper FFG to finalize a checkpoint $t$, there must exist a supermajority link from a justified checkpoint $t'$ to $t$, where $epoch(t) = epoch(t') + 1$. The sequence of attestations $\mathcal{A}$ represents the chain of justifications leading to this final link. Our algorithm's procedural check, $epoch(b_k) - epoch(b_{k-1}) = 1$, directly mirrors this requirement. The algorithm's output $(b_{k-1}, b_k)$ therefore corresponds to $(t', t)$, which is precisely the new (`finalized_checkpoint`, `current_justified_checkpoint`) state in Casper FFG.∎

This shows that our consensus algorithm will always be able to *follow* the Beacon chain's consensus, as long as there are no cases of 2-finality.


### **Theorem 2**
Let $s$ be a finalized checkpoint in a view $G$ of Casper FFG. Let $(f',c')$ denote the output of our algorithm when executed with the consensus state induced by $s$ and a valid set of supermajority links as input.
Under the accountable safety assumption ($< \frac{1}{3}$ of the validators by weight violate a slashing condition), $f'$ will also be finalized for $G$.

#### Proof Sketch:
This follows directly from Casper FFG's guarantee against finalizing conflicting checkpoints. Assume for contradiction that our algorithm finalizes $f'$ but $G$ does not. This would require $G$ to justify a pair of checkpoints $(a_m, a_{m+1})$ that "surround" the supermajority link $f' \to c'$ that our algorithm used.

The existence of both the link $f' \to c'$ and a surrounding link $a_m \to a_{m+1}$ is a slashable "surround vote" offense. Therefore, a supermajority of honest validators would never create this situation. Any valid view $G$ must respect the finalization of $f'$. ∎

While $f'$ is safe, $c'$ is only justified. Due to malicious behavior or network latency issues, a failure to justify $c'$ in $G$ is theoretically possible and would represent a liveness fault, not a safety violation.

## A Note on 2-Finality
This algorithm deliberately excludes cases of 2-finality, as they introduce significant complexity to our atomic, single-chain model.

The core challenge lies with finalization rules such as a supermajority link $b_{n-2} \to b_n$, which finalizes $b_{n-2}$. For this rule to be valid, both $b_{n-2}$ and $b_{n-1}$ must be justified. Our algorithm is designed to process one continuous chain of justifications from a single starting checkpoint ($c$), whereas a 2-finality rule would require verifying two distinct justification chains.

One might think the Beacon state's `previous_justified_checkpoint` and `current_justified_checkpoint` fields could serve as these two required checkpoints. However, this is not a reliable solution. The `previous_justified_checkpoint` field is defined as the `current_justified_checkpoint` of the previous epoch. This can lead to situations with an intermediate justified checkpoint that isn't captured by either field. For example, `previous_justified_checkpoint` could be $B_2$ and `current_justified_checkpoint` could become $B_4$, while $B_3$ was justified in the interim (*Case 1* and *Case 3* of Fig. 8. in Combining GHOST and Casper).

Fortunately, the FFG version implemented in the Ethereum Beacon Chain introduces practical constraints that simplify this problem. By only considering the justification status of the last four epochs and imposing other timing conditions, it prevents the most complex theoretical 2-finality scenarios from occurring. This ensures the conditions can be verified without needing a more complex algorithm that takes multiple justification chains as input.

Nevertheless, adapting our clean, single-chain model to formally handle even these simplified 2-finality rules would add considerable complexity. We therefore leave this extension for a future revision.
