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

use quote::format_ident;
use quote::quote;
use ssz_rs::GeneralizedIndexable;
use ssz_rs::Path;
use ssz_rs::PathElement;
use std::fs;
use std::io::Write;
use z_core::Ctx;

fn main() {
    let dest_filepath = std::path::Path::new("core/src/guest_context.rs");
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&dest_filepath)
        .unwrap();

    let gindices = beacon_gindices::<z_core::mainnet::ElectraBeaconState>();
    let consts = context_values();

    let tokens = gen_guest_context_impl("GuestContext", &consts, &gindices);

    let syntax_tree = syn::parse2(tokens).unwrap();
    let formatted = prettyplease::unparse(&syntax_tree);

    f.write(&formatted.into_bytes()).unwrap();
}

fn gen_guest_context_impl(
    struct_name: &str,
    methods: &[(String, String, proc_macro2::TokenStream)],
    gindices: &[(String, String, proc_macro2::TokenStream)],
) -> proc_macro2::TokenStream {
    let struct_ident = format_ident!("{}", struct_name);

    let method_impls = methods.iter().map(|(name, ret_type, value)| {
        let method_name = format_ident!("{}", name);
        let return_type = syn::parse_str::<syn::Type>(ret_type).unwrap();

        quote! {
            fn #method_name(&self) -> #return_type {
                #value as #return_type
            }
        }
    });

    let gindex_impls = gindices.iter().map(|(name, ret_type, value)| {
        let method_name = format_ident!("{}", name);
        let return_type = syn::parse_str::<syn::Type>(ret_type).unwrap();

        quote! {
            pub fn #method_name(&self) -> #return_type {
                #value
            }
        }
    });

    quote! {
        use crate::Ctx;

        #[derive(serde::Serialize, serde::Deserialize)]
        pub struct #struct_ident;

        impl Ctx for #struct_ident {
            type Error = ();
            #(#method_impls)*
        }

        impl #struct_ident {
            #(#gindex_impls)*

        }
    }
}

fn beacon_gindices<G>() -> Vec<(String, String, proc_macro2::TokenStream)>
where
    G: GeneralizedIndexable,
{
    // Static paths for the BeaconState
    [
        ("slot", Path::from(&["slot".into()])),
        (
            "genesis_validators_root",
            Path::from(&["genesis_validators_root".into()]),
        ),
        (
            "fork_current_version",
            Path::from(&["fork".into(), "current_version".into()]),
        ),
        ("validators", Path::from(&["validators".into()])),
        (
            "randao_mixes_0",
            Path::from(&["randao_mixes".into(), 0.into()]),
        ),
    ]
    .map(|(name, path)| gen_gindices::<G>(name.to_string(), path))
    .map(|(name, ret_type, value)| (format!("{name}_gindex"), ret_type, value))
    .to_vec()
}

fn context_values() -> Vec<(String, String, proc_macro2::TokenStream)> {
    let ctx: z_core::HostContext =
        ethereum_consensus::state_transition::Context::for_mainnet().into();
    [
        (
            "slots_per_epoch".to_string(),
            "u64".to_string(),
            ctx.slots_per_epoch(),
        ),
        (
            "effective_balance_increment".to_string(),
            "u64".to_string(),
            ctx.effective_balance_increment(),
        ),
        (
            "max_validators_per_committee".to_string(),
            "usize".to_string(),
            ctx.max_validators_per_committee() as u64,
        ),
        (
            "max_committees_per_slot".to_string(),
            "usize".to_string(),
            ctx.max_committees_per_slot() as u64,
        ),
        (
            "epochs_per_historical_vector".to_string(),
            "u64".to_string(),
            ctx.epochs_per_historical_vector(),
        ),
        (
            "min_seed_lookahead".to_string(),
            "u64".to_string(),
            ctx.min_seed_lookahead(),
        ),
        (
            "shuffle_round_count".to_string(),
            "u64".to_string(),
            ctx.shuffle_round_count(),
        ),
        (
            "target_committee_size".to_string(),
            "u64".to_string(),
            ctx.target_committee_size(),
        ),
        (
            "max_deposits".to_string(),
            "usize".to_string(),
            ctx.max_deposits() as u64,
        ),
    ]
    .map(|(name, ret_type, value)| (name, ret_type, quote!(#value)))
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
