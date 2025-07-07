# Safety Analysis of Balance Drift

## The Safety Margin Formula

### Key Variables and Notation

Let the trusted, finalized checkpoint be denoted by the pair $(f_0, epoch_0)$, and the target checkpoint whose finality is being proven be $(f_n, epoch_n)$. The number of elapsed epochs is $n = epoch_n - epoch_0$. We define the following:

* **Validator Sets:**
    * $V_0$: The set of active validators at $epoch_0$.
    * $V_n$: The set of active validators at $epoch_n$.
    * $A_n \subseteq V_n$: The subset of validators that have attested to the supermajority link required to justify $epoch_n$.

* **Total Active Balance:**
    * $\hat{B}_0$: The total **effective balance** of all validators in $V_0$, measured at $epoch_0$. This is the value `get_total_active_balance` would return at $epoch_0$.
    * $\hat{B}_n$: The total **effective balance** of all validators in $V_n$, measured at $epoch_n$.

* **Attesting Weight:**
    * $w_0(A_n)$: The sum of the effective balances of the validators in $A_n$, as measured from the trusted state at $epoch_0$. This is the value our zkVM guest program calculates.
    * $w_n(A_n)$: The sum of the effective balances of the validators in $A_n$, as measured by the canonical protocol at $epoch_n$. This is the value we are trying to safely reason about.

### Derivation

The canonical requirement for finality is that the attesting weight at $epoch_n$ meets the two-thirds threshold:
$$w_n(\mathcal{A}_n) \ge \frac{2}{3} \hat{B}_n$$

From the perspective of our guest at $epoch_0$, we must account for the maximum possible "balance drift". As slashings that occur after $epoch_0$ cannot be known from the trusted state, the total balance of these slashed validators must be provided as a separate input, $S$. We then define:

* **A**: The maximum possible *increase* in the effective balance of the **non-attesting** validators ($V_n \setminus A_n$) between $epoch_0$ and $epoch_n$.
* **E**: The maximum possible *decrease* in the effective balance of the **attesting** validators ($A_n$) between $epoch_0$ and $epoch_n$.
* **S**: The total effective balance of validators slashed between $epoch_0$ and $epoch_n$. While slashed validators are penalized, their balance still contributes to the total active balance ($\hat{B}_n$) for the supermajority calculation, but they are excluded from the attesting weight ($w_n$).

The safety condition, as viewed from $epoch_0$, can be expressed as:
$$w_0(\mathcal{A}_n) - E - S \ge \frac{2}{3} (\hat{B}_0 + A - E)$$

Rearranging this to solve for the required attesting weight $w_0(A_n)$ gives us our safety margin, $\delta$:
$$w_0(\mathcal{A}_n) \ge \frac{2}{3} \hat{B}_0 + \underbrace{\frac{1}{3}(2A + E) + S}_{\delta}$$
Thus, the safety margin is:
$$\delta = \frac{1}{3}(2A + E) + S$$

Unless otherwise stated, every $A$- or $E$-sub-term, and therefore $\delta$, itself is expressed in ETH. When a term is derived from a raw validator count we implicitly multiply by 1 ETH per validator.

## Bounding Balance Fluctuation Sources

We now derive conservative upper bounds for $A$ and $E$ over $n$ epochs, based on the Ethereum Electra specification.

### Validator Churn and Consolidations

* **Activations:** In the current model, the set of validators that can become active during the lookahead period $n$ is completely determined by the trusted state at $epoch_0$. A validator's activation requires that its `activation_eligibility_epoch` is less than or equal to the `finalized_checkpoint.epoch`. Since the `finalized_checkpoint` is fixed at $epoch_0$ for the entire verification process, any validator not already in the activation pipeline at $epoch_0$ cannot become active. Therefore, the increase in attesting weight from these known activations can be calculated precisely by the guest and is not a source of unbounded drift.
* **Exits & Consolidations:** For the zkVM guest to compute correct committee shuffles, it must account for any validator exits or consolidations that occur after the trusted checkpoint. This information is provided as part of the untrusted witness data. From the perspective of the validator registry, a voluntary exit and a consolidation are indistinguishable. To create a single, safe upper bound for balance churn, their respective churn limits must be combined. This combined value corresponds to the `get_balance_churn_limit` in the specification, which is based on the constant `CHURN_LIMIT_QUOTIENT` (65536). The official specification calculates this dynamic churn limit against the *current* total active balance at any given epoch $k$, with a floor of `MIN_PER_EPOCH_CHURN_LIMIT_ELECTRA` (128 ETH).
  To prevent a malicious prover from supplying fraudulent data, the guest program validates the witness against a hardcoded churn limit. Simply using a limit based on $\hat{B}_0$ could be unsafe, as the total active balance might increase over $n$ epochs, thus increasing the real churn limit. To account for this potential growth, the implementation uses a conservative factor of two. While a full formal analysis of this factor is complex, it serves as a safe, static bound for a reasonably small lookahead period $n$. Because the guest strictly enforces this specific check, our formal analysis must adopt the exact same bound:
    * $A_{churn} \le n \cdot 2 \cdot \max(128, \hat{B}_0 / 65536)$
    * $E_{churn} \le n \cdot 2 \cdot \max(128, \hat{B}_0 / 65536)$

### Rewards and Penalties

The total issuance per epoch is a function of the total active balance, $\hat{B}$ in Gwei. It is a [well-known](https://eth2book.info/capella/part2/incentives/issuance/#overall-issuance) design choice that per epoch the total issuance is
$$\hat{B} \cdot \frac{\text{BASE_REWARD_FACTOR}}{\sqrt{\hat{B}}} =64\sqrt{\hat{B}}\, \text{Gwei}$$
Even with a total active balance as high as 100 million ETH, the total issuance would be only a little over 20 ETH. For simplicity and to be highly conservative, we use a constant upper bound of **48 ETH per epoch** for both rewards and penalties. This is more than enough to account for future balance increases or "catch up" rewards for missed attestations due to skipped slots in the previous epoch
* **Rewards (contributing to A):** $A_{rewards} \le 48n$
* **Penalties (contributing to E):** $E_{penalties} \le 48n$

### Inactivity Leak Penalty

During a prolonged non-finality event (an "inactivity leak"), inactive validators are penalized with increasing severity. The penalty over $n$ epochs for validator $i$ with effective balance $B^i$ is $\sum_{k=4}^n \frac{B^i}{2^{24}}k$[^3]. This quadratic penalty growth is a key feature of the inactivity leak.

To derive a conservative upper bound for this penalty's contribution to $E$, we make the following worst-case assumptions:
1. All attesting validators in our set ($A_n$) are considered inactive from the beginning of the period.
2. The inactivity leak starts at the first epoch, i.e. we are not considering `MIN_EPOCHS_TO_INACTIVITY_PENALTY`.
3. The total balance of these attesting validators is bounded by the total active balance of the entire network, $\hat{B}_n$.

$$E_{inactivity} \le \left(\sum_{i \in \mathcal{A}_n} B^i\right) \cdot \frac{n(n+1)}{2 \cdot 2^{24}} \le \frac{\hat{B}_n \cdot n(n+1)}{33554432}$$

### Slashing

The slashing penalty has two parts: an initial penalty and a larger correlation penalty.

* **Initial Penalty:** This penalty is immediately applied but does not change the total active balance $\hat{B}_n$ (it's redistributed). Its primary effect is that the slashed validator's weight is removed from the attesting set $A_n$ (even though they may still attest), which is already captured by the term $S$ in our formula.
* **Correlation Penalty:** This is applied much later, after the validator is already withdrawable and thus no longer part of the active set. It can be ignored for this analysis.

### Hysteresis

The protocol updates a validator’s `effective_balance` only when
the actual `balance` crosses a hysteresis band.[^4] This creates two distinct sources of drift we must account for: a baseline drift from ordinary rewards and a large, event-driven jump from EIP-7251.
1. **Baseline Hysteresis Drift:** For any validator, ordinary rewards and penalties can cause their `balance` to cross a threshold, changing their `effective_balance` by at most 1 ETH. This creates a baseline drift potential for every validator in the set.
2. **EIP-7251 Compounding Switch:** With EIP-7251, a validator can submit a `ConsolidationRequest` to switch to compounding credentials, raising their maximum effective balance from `MIN_ACTIVATION_BALANCE` (32 ETH) to `MAX_EFFECTIVE_BALANCE_ELECTRA` (2048 ETH). This can trigger a one-time jump of up to 2016 ETH. However, the number of these "switch" events is strictly limited by the protocol. The `BeaconBlockBody` can contain at most `MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD` (2) per block. With 32 slots per epoch, a maximum of 64 switches can be processed per epoch.

To construct our final bound, we combine these two effects. We assume the worst case where all `64n` possible switches occur and all benefit non-attesting validators. Each switch contributes an *additional* 2015 ETH of drift on top of the 1 ETH baseline drift already accounted for.

* $A_{hysteresis} \le \underbrace{|V_n \setminus \mathcal{A}_n|}_{\text{Baseline Drift}} + \underbrace{(2015 \cdot 64n)}_{\text{EIP-7251 Jumps}} = |V_n \setminus \mathcal{A}_n| + 128960n$
* $E_{hysteresis} \le |\mathcal{A}_n|$ (The decrease remains bounded by the 1 ETH baseline drift)

## From Formal Model to Implemented Parameter

While this document derives a dynamic safety margin, $\delta$, the implementation employs a simplified, fixed supermajority threshold. For instance, the default configuration requires a justification of **85%** (`justification_threshold_factor: 85`, `justification_threshold_quotient: 100`).

This fixed threshold is not an alternative to the $\delta$ analysis; it is a **practical parameter chosen based on it**. The formal derivation of $\delta$ allows us to calculate the worst-case balance drift for the configured `epoch_lookahead_limit`. The implemented 85% threshold is a conservative value chosen to exceed $2/3 + \delta$ for all permissible lookahead scenarios, thereby guaranteeing safety without requiring the zkVM guest to perform the complex $\delta$ calculation at runtime. The formal analysis thus serves as the fundamental justification for the safety of the implemented fixed threshold.

### Bounding the Total Safety Margin

By combining the individual components for the maximum possible increase in non-attesting weight ($A$) and the maximum decrease in attesting weight ($E$), we get the following bounds:

$$A = A_{churn} + A_{rewards} + A_{hysteresis}$$ $$\leq 2n\max(128,\frac{\hat{B}_0}{65536})+ 48n + |\mathcal{V}_n \setminus \mathcal{A}_n|+128960n$$
$$E = E_{churn} + E_{penalties} + E_{inactivity} + E_{hysteresis}$$ $$\leq 2n\max(128,\frac{\hat{B}_0}{65536}) + 48n + \frac{\hat{B}_n n(n+1)}{33554432} + |\mathcal{A}_n|$$

Substituting these into the safety margin formula, $\delta = \frac{1}{3}(2A + E) + S$, yields the final comprehensive bound:
$$\delta \le 48n + 2n\max(128,\frac{\hat{B}_0}{65536}) + \frac{\hat{B}_n n(n+1)}{100663296}  + \frac{2}{3}|\mathcal{V}_n| + 85973n + S$$


To make this formula computable, we replace the unknown values at epoch $n$ with conservative upper bounds derived from the trusted state at $epoch_0$. While the balance from validators activating during the lookahead period can be calculated precisely, it is simpler for the purpose of this meta-analysis to use a conservative upper bound. The upper bound for the total active balance $\hat{B}_n$ is thus composed of the initial balance, a bound on balance from new activations (`MAX_PER_EPOCH_ACTIVATION_EXIT_CHURN_LIMIT`), the maximum rewards, and the maximum hysteresis drift:

$$\hat{B}_n \le \hat{B}_0 + \underbrace{(256 \cdot n)}_{\text{queued activations}} + \underbrace{(48 \cdot n)}_{\text{rewards}} + \underbrace{(|V_0|+128960\cdot n)}_{\text{hysteresis}}$$

Similarly, the upper bound for the number of validators is:

$$|V_n| \le |V_0| + (8 \cdot n)$$

The resulting safety margin $\delta$ can be calculated programmatically as shown in the Python implementation below.

```python
def calculate_delta(B_0: int, V_0: int, S: int, n: int) -> int:
    """
    Calculates a conservative safety margin delta for TSEth.

    Args:
        B_0: Total active effective balance at the trusted epoch (in ETH).
        V_0: Number of active validators at the trusted epoch.
        S: Total slashed balance since the trusted epoch (in ETH).
        n: Number of epochs to look ahead.
    """
    # An upper bound for the total active balance at the target epoch
    # +V_0  (≤1 ETH hysteresis jump per validator)
    B_n = B_0 + (256 * n) + (48 * n) + V_0 + 128960 * n
    # An upper bound for the active validators at the target epoch
    V_n = V_0 + (8 * n)

    churn_term = n * 2 * max(128, B_0 / 65536)
    reward_term = 48 * n
    inactivity_term = (B_n * n * (n + 1)) / 100663296
    hysteresis_term = 2 * (V_n + 128960 * n) / 3

    delta = reward_term + churn_term + inactivity_term + hysteresis_term + S

    # Return the final margin, rounded up for a conservative estimate.
    return math.ceil(delta)
```

### Conclusion

This analysis provides a self-contained, conservative bound for the safety margin $\delta$, depending only on the initial state at $epoch_0$, the slashed balance $S$, and the lookahead period $n$. The model's robustness is best illustrated by examining its sensitivity to these parameters.

With the current TSEth default configuration requiring ≥85% voting participation and a finalization lookahead of at most 10 epochs, the system maintains strong security guarantees. For instance, using Ethereum mainnet data from July 2025 (35,475,927 ETH staked by 1,087,747 active validators), TSEth can safely finalize checkpoints even if validators with a combined effective balance of over 4.9 million ETH were slashed.

The safety margin is most sensitive to the lookahead period, $n$. While a short lookahead results in a modest $\delta$, the margin grows quadratically as $n$ increases due to the inactivity leak term, demonstrating the importance of the configured `epoch_lookahead_limit`. Similarly, the model correctly scales with the total slashed balance, $S$, ensuring that large-scale slashing events are safely accounted for. This framework provides a transparent and verifiable method for ensuring the safety of a ZKVM-based FFG implementation.

[^1]: [def_process_justification_and_finalization](https://eth2book.info/capella/part3/transition/epoch/#def_process_justification_and_finalization)
[^3]: [inactivity-penalty-deltas](https://eth2book.info/capella/part3/transition/epoch/#inactivity-penalty-deltas)
[^4]: [process_effective_balance_updates](https://eth2book.info/capella/part3/transition/epoch/#def_process_effective_balance_updates)
