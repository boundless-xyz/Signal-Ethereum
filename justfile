MAINNET_ELECTRA_SLOT := "11649026" # two epochs after the fork, otherwise we will need pre-fork state to process attestations
SEPOLIA_ELECTRA_SLOT := "7118912" # two epochs after the fork, otherwise we will need pre-fork state to process attestations

test-sync network slot:
    cargo run -r --bin zkasper_cli --no-default-features --features {{network}} -- --network {{network}} sync --start-slot {{slot}} --log-path ./logs/{{network}}.log --mode ssz

test-sync-full-mainnet:
    @echo "Testing sync on mainnet from slot $(MAINNET_ELECTRA_SLOT)"
    just test-sync "mainnet" {{MAINNET_ELECTRA_SLOT}}

test-sync-full-sepolia:
    @echo "Testing sync on sepolia from slot $(SEPOLIA_ELECTRA_SLOT)"
    just test-sync "sepolia" {{SEPOLIA_ELECTRA_SLOT}}
