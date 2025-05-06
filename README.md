# ZKasper 

Validity proofs of Ethereum's finality gadget (Casper FFG). 

## Building
```
cargo build -r
```

## Daemon Mode
Daemon mode listens to the chain for new block events. When a new finalization event happens, the daemon will download the beacon state and save it to disk. To be able to generate proofs, listen to the chain for 3-4 epochs by running 

```
RUST_LOG=info ./target/release/host --beacon-api="<BEACON_URL>" daemon
```
The daemon mode should eventually do what it is currently doing right now, but also make proofs whenever every epoch automatically. 

## Exec Command
After a few epochs worth of beacon states are saved, we can finalize some candidate checkpoint using Casper FFG

```
RISC0_INFO=1 RUST_LOG=info ./target/release/host --trusted-epoch=<TRUSTED_CHECKPOINT> --beacon-api="<BEACON_URL>" exec
```
where `TRUSTED_CHECKPOINT` is the epoch at which the first epoch that was saved by running the daemon. 

This will run the Casper FFG verification 3 times. 
The first time, FFG is run with a TrackingStateReader which is backed by beacon states saved on disk to track the important parts in the beacon state that we will need. After the first run, a SszStateReader will be created from the TrackingStateReader. The SszStateReader is used to run FFG again on the host as a sanity check as this is what will be sent as input to the guest program. Finally FFG is run again but in the R0VM executor.