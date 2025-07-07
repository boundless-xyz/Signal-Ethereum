# The Signal: Ethereum

A ZKVM-friendly implementation of [Casper FFG](https://arxiv.org/abs/2003.03052), the finality gadget used by the Ethereum beacon chain. This forms part of [The Signal](https://github.com/boundless-xyz/signal) a project to prove the consensus of all chains.

## Background

Like Casper, Signal.Ethereum operates over the abstraction of checkpoints and attested links rather than blocks and epochs. The ZKVM program allows a prover to construct a proof that they have seen sufficient attestations for a link(s) that can transition a given consensus state (previous, current, and finalized checkpoints) to a new consensus state. Starting from a trusted consensus state, a client verifying these proofs can update its view of the latest finalized checkpoint which can be used as a root of trust for proofs into the finalized blockchain.

### Important Considerations

If using Signal.Ethereum to build a bridge or a light-client it is important to understand the guarantees/assumptions and how these differ from a regular beacon chain client.

- By default Signal.Ethereum does not allow for making arguments about the economic security of the checkpoints it has finalized. This is because the attestations do not form part of the public journal and so any violations by validators cannot be observed and slashed. A bridge using Signal.Ethereum may wish to include proofs of data availability of the relevant attestations and also proof that they are within the slashability period of the chain where the validator deposits are held. In this case economic security arguments could be made.

- There is no long-range attack protection from the proofs alone. Similar to the above consumers of Signal.Ethereum proofs need to ensure they only accept state transitions while within the slashability period of the supermajority of attesting validators. They should also ensure that very long range updates (e.g. longer than the weak-subjectivity period) are not allowed.

- The implementation currently supports the Electra hard-fork only. Attempting to process epochs prior to this fork will fail. Due to how attestations are structured pre-Electra verifying them is much more expensive (around 100x) and so pre-Electra will likely not be supported.

## Repository Structure

Key components:

- **core**: Crate implementing the core logic of Signal.Ethereum. [./core](./core)
- **methods/guest**: Guest program code. [./methods/guest](./methods/guest)
- **host**: Crate for building inputs for Signal.Ethereum given a beacon RPC and for executing the guest. Includes a CLI tool (see below). [./host](./host)
- **ssz-multiproofs**: Crate implementing a builder, serialization, and efficient verifier of SSZ multi-proofs of inclusion. [./ssz-multiproofs](./ssz-multiproofs)
- **chainspec**: A crate for loading Ethereum beacon chain configurations. [./chainspec](./chainspec)

## Developing

If you don't already have Rust installed, start by [installing Rust and rustup](https://doc.rust-lang.org/cargo/getting-started/installation.html).

Then download the RISC Zero toolchain and install it using rzup:

```sh
curl -L https://risczero.com/install | bash
```

Next we can install the RISC Zero toolchain by running rzup install:

```sh
rzup install
```

You can verify the installation was successful by running:

```sh
cargo risczero --version
```

To build the Rust crates, run:

```sh
cargo build
```

## Testing

Project wide tests can be run with

```sh
cargo test
```

## Host CLI

The host CLI tool can be run with

```sh
cargo run --bin host
```

```sh
CLI for generating and submitting Signal.Ethereum proofs

Usage: host [OPTIONS] --beacon-api <BEACON_API> <COMMAND>

Commands:
  verify  Runs FFG verification in R0VM Executor
  sync    Attempts to sync a trusted block root to the latest state available on the Beacon API Optionally can log any places the resulting consensus state diverges from the chain for debugging
  help    Print this message or the help of the given subcommand(s)

Options:
      --beacon-api <BEACON_API>  Beacon API URL [env: BEACON_RPC_URL]
  -r, --rps <RPS>                Max Beacon API requests per second (0 to disable rate limit) [default: 0]
  -n, --network <NETWORK>        Network name [default: sepolia] [possible values: mainnet, sepolia]
  -d, --data-dir <DATA_DIR>      Directory to store data [default: ./data]
  -h, --help                     Print help
  -V, --version                  Print version
```

> [!TIP]
> The host CLI tool requires a beacon chain RPC url either via the BEACON_RPC_URL env var or the --beacon-api flag.
> This RPC must support the [Debug](https://ethereum.github.io/beacon-APIs/#/Debug) endpoints and, unless operating near the tip of the chain,
> must support access to historical beacon states (e.g. an archive node). 
> [Quicknode](https://www.quicknode.com/)(unaffiliated) is one public RPC provider that is known to work. 

## License

See [LICENSE](./LICENSE).
