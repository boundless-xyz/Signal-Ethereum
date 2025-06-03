# ZKasper Safety and Liveness

ZKasper only considers the Casper finality gadget component of the beacon chain starting from one trusted state.

Finalizing another state requires verifying attestations in future epochs where the state is not available, and could not be trusted if it was. Instead of processing blocks to get these intermediate states like a full node would, ZKasper accepts a number of state patches which capture the minimal changes which must be made to the trusted state in order to obtain a state which can be used to verify the attestations in future epochs.

Two things are needed to verify that a set of attestations reached a supermajority, the RANDO values used to compute the shuffle, and the active validator set. These are the two things that can be modified by a patch.

Leaving the RANDO as a free parameter is ok because it only allocates validators between committees which are aggregated together at the epoch level anyway. It cannot change the attesting balance for a link.

The active validator set changes will be the focus of the rest of this document

## Mental Model

One way to think of this is that the real beacon chain can churn active validators between epochs and ZKasper can do this as well via introducing a prover degree of freedom in a state patch.

In an ideal world ZKasper has sufficient freedom to follow the beacon chain under all conditions (ideal liveness).

We also want to ensure that a malicious prover can't convince a ZKasper client to finalize a checkpoint that was not finalized by the beacon chain (ideal safety).

> It should be noted that we cannot have ideal safety and liveness under the same assumption as the beacon chain ($2/3$ of the stake is honest) due to the ability of a dishonest prover to manipulate the validator set up to the maximum amount of freedom at no cost. 

## Frozen validator set

One option is to not allow any degree of freedom to the prover when it comes to the validators set. We will call this the frozen validator set case. ZKasper assumes no changes to the validator set in future epochs and attempts to verify future attestations using this potentially outdated set.

### Liveness

If the beacon chain can churn at most $C$ worth of stake per epoch this means that $C$ of the actual $\text{attestingBalance}$ might be unaccounted for by ZKasper even if the beacon chain is counting its weight when computing vote weight for a link. We therefore an additional buffer of $C$ worth of votes in the beacon chain to ensure ZKasper will still be able to form a supermajority link in the worst case.

Or put differently instead of requiring some fraction of total balance, $w = \frac{\text{attestingBalance}}{\text{totalActiveBalance}}$, to exceed the threshold, $p$, of active balance (set to $2/3$ for the beacon chain) we need there to be

$$w \geq p + \frac{C}{\text{totalActiveBalance}}$$

worth of available votes to ensure ZKasper can count a threshold, $p$, of votes using its outdated state.

This is per epoch so the number of epochs ZKasper needs to lookahead to find a finalizing supermajority link is also a factor. This is additive in the worst case so for lookahead of $L$ epochs we require the beacon chain to have 

$$
w \geq p + \frac{L C}{\text{totalActiveBalance}}
$$

of the stake voting on a supermajority link to ensure that Zkasper will always remain live.

### Safety

A frozen validator set also means that $C$ worth of stake of validators who may have exited can sign malicious attestations with no risk of slashing but ZKasper will believe they are still active and able to be penalized.

There are two options here. Either accept this and adjust the assumptions under which ZKasper is safe ($p + \frac{L C}{totalActiveBalance}$ of stake is honest), or we can adjust ZKaspers supermajority threshold, $p_{zk}$, to be different to the beacon chain. This allows sacrificing some of the liveness bound to get ideal safety.

If we set $p_{zk} = p + \frac{LC}{totalActiveBalance}$ we get ideal safety again.

Substituting that into the equation above we therefore need the beacon chain to be voting at least

$$
w \geq p + \frac{2 L C}{\text{totalActiveBalance}}
$$

to ensure liveness in the worst case while ensuring ideal safety.

## What is $C$ for the beacon chain?

Post-electra the churn is calculated in balance rather than in number of validators as

```python
def get_balance_churn_limit(state: BeaconState) -> Gwei:
    """
    Return the churn limit for the current epoch.
    """
    churn = max(
        MIN_PER_EPOCH_CHURN_LIMIT_ELECTRA,
        get_total_active_balance(state) // CHURN_LIMIT_QUOTIENT
    )
    return churn - churn % EFFECTIVE_BALANCE_INCREMENT
```

So it is a function of active balance.

At a recent epoch (369363) we have

- CHURN_LIMIT_QUOTIENT = 65536
- get_total_active_balance = 34402895 Eth
- churn = 525 Eth

> Assumes rewards and slashings are negligible in relation to the max churn. Is this safe to do?

## Analysis

Using the above we can calculate that to ensure ZKasper can safely accept a supermajory link it must have received vote weight fraction

$w(L) = 2/3 + L \frac{2*16*32}{1055350} = 2/3 + L 9.7e-4$

Or we need minimum 66.6% plus additional 0.097% per epoch we want to look ahead to ensure liveness while maintaining ideal safety.

This suggests it can lookahead roughly 300 epochs provided validator participation is close to 100%. Or finalize in 3 epochs (the typical case) provided the validator participation is > ~66.9%. 

Plot of required validator participation fraction, $w$, as a function of epochs lookahead, $L$.

<iframe src="https://www.desmos.com/calculator/2ntenpf9te?embed" width="500" height="500" style="border: 1px solid #ccc" frameborder=0></iframe>
