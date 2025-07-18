use beacon_types::{
    AbstractExecPayload, BeaconState, ChainSpec, EthSpec, Hash256, SignedBeaconBlock,
};
use state_processing::{
    AllCaches, BlockProcessingError, BlockSignatureStrategy, BlockSignatureVerifier,
    ConsensusContext, VerifyBlockRoot, per_block_processing, state_advance::complete_state_advance,
};
use tracing::debug;

#[derive(thiserror::Error, Debug, PartialEq)]
pub enum Error {
    #[error("Invalid attestation: {0:?}")]
    BlockProcessing(BlockProcessingError),
    #[error("Other: {0}")]
    Other(String),
}

impl From<BlockProcessingError> for Error {
    fn from(e: BlockProcessingError) -> Self {
        Error::BlockProcessing(e)
    }
}
impl From<String> for Error {
    fn from(e: String) -> Self {
        Error::Other(e)
    }
}
impl From<&str> for Error {
    fn from(e: &str) -> Self {
        Error::Other(e.to_string())
    }
}

#[derive(Debug)]
pub struct ProcessingConfig {
    pub no_signature_verification: bool,
    pub exclude_cache_builds: bool,
    pub exclude_post_block_thc: bool,
}

pub fn do_transition<E: EthSpec>(
    mut pre_state: BeaconState<E>,
    block_root: Hash256,
    block: SignedBeaconBlock<E>,
    mut state_root_opt: Option<Hash256>,
    config: &ProcessingConfig,
    // validator_pubkey_cache: &ValidatorPubkeyCache<EphemeralHarnessType<E>>,
    saved_ctxt: &mut Option<ConsensusContext<E>>,
    spec: &ChainSpec,
) -> Result<BeaconState<E>, Error> {
    if !config.exclude_cache_builds {
        let t = std::time::Instant::now();
        pre_state
            .build_all_caches(spec)
            .map_err(|e| format!("Unable to build caches: {:?}", e))?;
        debug!("Build caches: {:?}", t.elapsed());

        let t = std::time::Instant::now();
        let state_root = pre_state
            .update_tree_hash_cache()
            .map_err(|e| format!("Unable to build tree hash cache: {:?}", e))?;
        debug!("Initial tree hash: {:?}", t.elapsed());

        if state_root_opt.is_some_and(|expected| expected != state_root) {
            return Err(format!(
                "State root mismatch! Expected {}, computed {}",
                state_root_opt.unwrap(),
                state_root
            )
            .into());
        }
        state_root_opt = Some(state_root);
    }
    let state_root = state_root_opt.ok_or("Failed to compute state root, internal error")?;

    // Transition the parent state to the block slot.
    let t = std::time::Instant::now();
    complete_state_advance(&mut pre_state, Some(state_root), block.slot(), spec)
        .map_err(|e| format!("Unable to perform complete advance: {e:?}"))?;
    debug!("Slot processing: {:?}", t.elapsed());

    // Slot and epoch processing should keep the caches fully primed.
    assert!(pre_state.all_caches_built());

    let t = std::time::Instant::now();
    pre_state
        .build_all_caches(spec)
        .map_err(|e| format!("Unable to build caches: {:?}", e))?;
    debug!("Build all caches (again): {:?}", t.elapsed());

    let mut ctxt = if let Some(ctxt) = saved_ctxt {
        ctxt.clone()
    } else {
        let ctxt = ConsensusContext::new(pre_state.slot())
            .set_current_block_root(block_root)
            .set_proposer_index(block.message().proposer_index());
        ctxt
    };

    // if !config.no_signature_verification {
    //     let get_pubkey = move |validator_index| {
    //         validator_pubkey_cache
    //             .get(validator_index)
    //             .map(Cow::Borrowed)
    //     };

    //     let decompressor = move |pk_bytes| {
    //         // Map compressed pubkey to validator index.
    //         let validator_index = validator_pubkey_cache.get_index(pk_bytes)?;
    //         // Map validator index to pubkey (respecting guard on unknown validators).
    //         get_pubkey(validator_index)
    //     };

    //     let t = std::time::Instant::now();
    //     BlockSignatureVerifier::verify_entire_block(
    //         &pre_state,
    //         get_pubkey,
    //         decompressor,
    //         &block,
    //         &mut ctxt,
    //         spec,
    //     )
    //     .map_err(|e| format!("Invalid block signature: {:?}", e))?;
    //     debug!("Batch verify block signatures: {:?}", t.elapsed());

    //     // Signature verification should prime the indexed attestation cache.
    //     assert_eq!(
    //         ctxt.num_cached_indexed_attestations(),
    //         block.message().body().attestations_len()
    //     );
    // }

    let t = std::time::Instant::now();
    per_block_processing(
        &mut pre_state,
        &block,
        BlockSignatureStrategy::NoVerification,
        VerifyBlockRoot::True,
        &mut ctxt,
        spec,
    )
    .map_err(|e| format!("State transition failed: {:?}", e))?;
    debug!("Process block: {:?}", t.elapsed());

    if !config.exclude_post_block_thc {
        let t = std::time::Instant::now();
        pre_state
            .update_tree_hash_cache()
            .map_err(|e| format!("Unable to build tree hash cache: {:?}", e))?;
        debug!("Post-block tree hash: {:?}", t.elapsed());
    }

    Ok(pre_state)
}
