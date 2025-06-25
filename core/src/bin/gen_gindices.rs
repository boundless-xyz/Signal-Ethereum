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

use ethereum_consensus::electra::Validator;
use ethereum_consensus::electra::mainnet::VALIDATOR_REGISTRY_LIMIT;
use quote::format_ident;
use quote::quote;
use ssz_rs::GeneralizedIndexable;
use ssz_rs::List;
use ssz_rs::Path;
use ssz_rs::PathElement;
use std::fs;
use std::io::Write;

fn main() {
    let dest_filepath = std::path::Path::new("core/src/guest_gindices.rs");
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(dest_filepath)
        .unwrap();

    let state_fns =
        gen_guest_gindices_impl(&beacon_gindices::<z_core::mainnet::ElectraBeaconState>());
    let block_fns = gen_guest_gindices_impl(&block_gindices::<
        ethereum_consensus::electra::BeaconBlockHeader,
    >());
    let validators_fns = validators_gindices();

    let tokens = quote! {
        #state_fns
        #block_fns
        #validators_fns
    };

    let syntax_tree = syn::parse2(tokens).unwrap();
    let formatted = prettyplease::unparse(&syntax_tree);

    let _ = f.write(&formatted.into_bytes()).unwrap();
}

fn gen_guest_gindices_impl(
    gindices: &[(String, String, String, proc_macro2::TokenStream)],
) -> proc_macro2::TokenStream {
    let gindex_impls = gindices.iter().map(|(name, ret_type, root, value)| {
        let method_name = format_ident!("{}_gindex", name);
        let return_type = syn::parse_str::<syn::Type>(ret_type).unwrap();
        let comment = format!(" Returns the gindex of {} from {}", name, root);
        quote! {
            #[doc = #comment]
            #[inline(always)]
            pub(crate) const fn #method_name() -> #return_type {
                #value
            }
        }
    });

    quote! {
        #(#gindex_impls)*
    }
}

fn validators_gindices() -> proc_macro2::TokenStream {
    let base_gindex =
        <List<Validator, VALIDATOR_REGISTRY_LIMIT>>::generalized_index(Path::from(&[0.into()]))
            .unwrap() as u64;

    let validator_chunk_count = Validator::chunk_count() as u64;

    // static paths for the Validator
    let g = [
        ("public_key_0", Path::from(&["public_key".into(), 0.into()])),
        (
            "public_key_1",
            Path::from(&["public_key".into(), 47.into()]),
        ),
        (
            "effective_balance",
            Path::from(&["effective_balance".into()]),
        ),
        (
            "activation_eligibility_epoch",
            Path::from(&["activation_eligibility_epoch".into()]),
        ),
        ("activation_epoch", Path::from(&["activation_epoch".into()])),
        ("exit_epoch", Path::from(&["exit_epoch".into()])),
        ("slashed", Path::from(&["slashed".into()])),
    ]
    .map(|(name, path)| gen_gindices::<Validator>(name.to_string(), path))
    .map(|(name, ret_type, value)| (format!("{name}"), ret_type, quote!(#value)))
    .to_vec();

    let v: proc_macro2::TokenStream = g
        .into_iter()
        .map(|(name, ret_type, value)| {
            let method_name = format_ident!("{}_gindex", name);
            let return_type = syn::parse_str::<syn::Type>(&ret_type).unwrap();
            let comment = format!(" Returns the gindex of {} from Validator i", name);
            quote! {
                    #[doc = #comment]
                    #[inline(always)]
                    pub(crate) const fn #method_name(i: crate::ValidatorIndex) -> #return_type {
                        const CHUNK_OFFSET: u64 = #value / #validator_chunk_count;
                        const WITHIN_CHUNK: u64 = #value % #validator_chunk_count;
                        (#base_gindex + (i as u64)) * #validator_chunk_count * CHUNK_OFFSET + WITHIN_CHUNK
                    }
                }
        })
        .collect();

    quote! {

        #v
    }
}

fn block_gindices<G>() -> Vec<(String, String, String, proc_macro2::TokenStream)>
where
    G: GeneralizedIndexable,
{
    // Static paths for the BeaconBlock
    [("state_root", Path::from(&["state_root".into()]))]
        .map(|(name, path)| gen_gindices::<G>(name.to_string(), path))
        .map(|(name, ret_type, value)| {
            (
                format!("{name}"),
                ret_type,
                "BeaconBlock".to_string(),
                value,
            )
        })
        .to_vec()
}

// Returns name, return type, the root of the path, and value
fn beacon_gindices<G>() -> Vec<(String, String, String, proc_macro2::TokenStream)>
where
    G: GeneralizedIndexable,
{
    // Static paths for the BeaconState
    [
        ("slot", Path::from(&["slot".into()])),
        (
            "finalized_checkpoint_epoch",
            Path::from(&["finalized_checkpoint".into(), "epoch".into()]),
        ),
        (
            "genesis_validators_root",
            Path::from(&["genesis_validators_root".into()]),
        ),
        (
            "fork_previous_version",
            Path::from(&["fork".into(), "previous_version".into()]),
        ),
        (
            "fork_current_version",
            Path::from(&["fork".into(), "current_version".into()]),
        ),
        ("fork_epoch", Path::from(&["fork".into(), "epoch".into()])),
        ("validators", Path::from(&["validators".into()])),
        (
            "earliest_exit_epoch",
            Path::from(&["earliest_exit_epoch".into()]),
        ),
        (
            "earliest_consolidation_epoch",
            Path::from(&["earliest_consolidation_epoch".into()]),
        ),
    ]
    .map(|(name, path)| gen_gindices::<G>(name.to_string(), path))
    .map(|(name, ret_type, value)| {
        (
            format!("{name}"),
            ret_type,
            "BeaconState".to_string(),
            value,
        )
    })
    .to_vec()
}

fn gen_gindices<G>(name: String, path: &[PathElement]) -> (String, String, proc_macro2::TokenStream)
where
    G: GeneralizedIndexable,
{
    (name, "u64".to_string(), {
        let gindex = G::generalized_index(path).unwrap() as u64;
        quote!(#gindex)
    })
}
