use syn::{parse2, ItemFn};
use quote::quote;
use proc_macro::TokenStream;

#[proc_macro_attribute]
pub fn trace(_attr: TokenStream, item: TokenStream) -> TokenStream {
    trace_impl(_attr.into(), item.into()).into()
}

fn trace_impl(
    _attr: proc_macro2::TokenStream,
    item: proc_macro2::TokenStream
) -> proc_macro2::TokenStream {
    let input_function: ItemFn = parse2(item).unwrap();

    let vis = input_function.vis;
    let name = input_function.sig.ident;
    let arguments = input_function.sig.inputs;
    let output = input_function.sig.output;
    let block = input_function.block;

    quote! {
        #vis fn #name(#arguments) #output {
            println!("[TRACE] entering function: {}", stringify!(#name));
            let result = (|| #block)();
            println!("[TRACE] exiting function: {}", stringify!(#name));
            result
        }
    }.into()
}
