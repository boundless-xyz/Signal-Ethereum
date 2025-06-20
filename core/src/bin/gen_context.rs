use quote::format_ident;
use quote::quote;
use ssz_rs::GeneralizedIndexable;
use ssz_rs::Path;
use ssz_rs::PathElement;
use std::fs;
use std::io::Write;

fn main() {
    let dest_filepath = std::path::Path::new("core/src/guest_context.rs");
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&dest_filepath)
        .unwrap();

    let gindices = beacon_gindices::<z_core::mainnet::ElectraBeaconState>();

    let tokens = gen_guest_context_impl(&gindices);

    let syntax_tree = syn::parse2(tokens).unwrap();
    let formatted = prettyplease::unparse(&syntax_tree);

    f.write(&formatted.into_bytes()).unwrap();
}

fn gen_guest_context_impl(
    gindices: &[(String, String, proc_macro2::TokenStream)],
) -> proc_macro2::TokenStream {
    let gindex_impls = gindices.iter().map(|(name, ret_type, value)| {
        let method_name = format_ident!("{}", name);
        let return_type = syn::parse_str::<syn::Type>(ret_type).unwrap();

        quote! {
            pub fn #method_name() -> #return_type {
                #value
            }
        }
    });

    quote! {

            #(#gindex_impls)*

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
            "randao_mixes_0",
            Path::from(&["randao_mixes".into(), 0.into()]),
        ),
    ]
    .map(|(name, path)| gen_gindices::<G>(name.to_string(), path))
    .map(|(name, ret_type, value)| (format!("{name}_gindex"), ret_type, value))
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
