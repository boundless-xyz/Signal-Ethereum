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

fn main() {
    let dest_filepath = std::path::Path::new("core/src/guest_gindices.rs");
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(dest_filepath)
        .unwrap();

    let gindices = beacon_gindices::<z_core::mainnet::ElectraBeaconState>();

    let tokens = gen_guest_gindices_impl(&gindices);

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
