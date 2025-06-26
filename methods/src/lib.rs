// Copyright 2025 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

include!(concat!(env!("OUT_DIR"), "/methods.rs"));

#[cfg(feature = "host")]
pub mod host {
    use anyhow::Context;
    use risc0_zkvm::{ExecutorEnv, default_executor};
    use tracing::{debug, info};
    use z_core::{ConsensusState, EthSpec, Input, StateInput};

    /// Runs the verification method in the RISC Zero VM, handling the serialization and deserialization
    pub fn vm_verify<S: EthSpec>(
        spec: String,
        state_input: &StateInput,
        input: &Input<S>,
    ) -> Result<(ConsensusState, ConsensusState), anyhow::Error> {
        info!("Running host verification");

        let input_bytes = bincode::serialize(input).context("failed to serialize input")?;
        debug!(len = input_bytes.len(), "Input serialized");

        let state_bytes =
            bincode::serialize(state_input).context("failed to serialize state reader")?;
        debug!(len = state_bytes.len(), "State reader serialized");

        let journal = execute_guest_program(spec, state_bytes, input_bytes)
            .context("guest verification failed")?;

        // decode the journal
        let (pre_state, post_state) = journal.split_at(ConsensusState::abi_encoded_size());
        let pre_state = ConsensusState::abi_decode(pre_state).context("invalid journal")?;
        let post_state = ConsensusState::abi_decode(post_state).context("invalid journal")?;

        Ok((pre_state, post_state))
    }

    fn execute_guest_program(
        spec: String,
        state: impl AsRef<[u8]>,
        input: impl AsRef<[u8]>,
    ) -> anyhow::Result<Vec<u8>> {
        let elf = match spec.as_str() {
            "mainnet" => super::BEACON_GUEST_MAINNET_ELF,
            "sepolia" => super::BEACON_GUEST_SEPOLIA_ELF,
            "test" => super::BEACON_GUEST_TESTHARNESS_ELF,
            _ => return Err(anyhow::anyhow!("Unsupported spec: {}", spec)),
        };
        let env = ExecutorEnv::builder()
            .write_frame(state.as_ref())
            .write_frame(input.as_ref())
            .build()?;
        let executor = default_executor();
        let session_info = executor.execute(env, elf)?;
        debug!(cycles = session_info.cycles(), "Session info");

        Ok(session_info.journal.bytes)
    }
}
