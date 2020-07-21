use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, parse_quote, DeriveInput, GenericParam, Generics, Data, Field, Attribute, Path, Ident, Meta, NestedMeta};
use syn::group::Group;
use std::fmt::{self, Display};
mod zeruformatter;
use quote::ToTokens;
use serde::Serialize;

#[derive(Copy, Clone)]
struct Symbol(&'static str);

impl PartialEq<Symbol> for Ident {
	fn eq(&self, word: &Symbol) -> bool {
			self == word.0
	}
}

impl<'a> PartialEq<Symbol> for &'a Ident {
	fn eq(&self, word: &Symbol) -> bool {
			*self == word.0
	}
}

impl PartialEq<Symbol> for Path {
	fn eq(&self, word: &Symbol) -> bool {
			self.is_ident(word.0)
	}
}

impl<'a> PartialEq<Symbol> for &'a Path {
	fn eq(&self, word: &Symbol) -> bool {
			self.is_ident(word.0)
	}
}

impl Display for Symbol {
	fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
			formatter.write_str(self.0)
	}
}

const SIGN: Symbol = Symbol("sign");
const SKIP: Symbol = Symbol("skip");
const SIGNATURE: Symbol = Symbol("signature");

#[derive(PartialEq)]
enum Attr {
	None,
	Skip,
	Signature,
	// TODO: give feedback to user when encountering unrecognized attributes
	Unrecognized,
}

impl Attr {
	fn should_be_signed(&self) -> bool {
		match self {
			Attr::None => true,
			Attr::Skip => false,
			Attr::Signature => false,
			Attr::Unrecognized => true,
		}
	}
}

/// Derive Sign.
/// ```
/// use serde_derive::{Serialize, Deserialize};
/// use zerusign::Sign;
/// use zerusign_derive::*;
/// use zerucrypt;
///
/// pub fn is_default<T: Default + PartialEq>(t: &T) -> bool {
/// 	t == &T::default()
/// }
///
/// #[derive(Serialize, Deserialize, Sign, Default)]
/// struct MyStruct {
/// 	data: String,
/// 	#[serde(skip_serializing_if = "is_default")]
/// 	#[sign(signature)]
/// 	sign: String,
/// 	#[sign(skip)]
/// 	skipped_field: bool,
/// }
///
/// fn main () {
/// 	let mut my_struct = MyStruct{
/// 		data: "random_data".to_string(),
/// 		sign: String::new(),
/// 		skipped_field: true,
/// 	};
/// 	let key = "5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss";
/// 	let result = my_struct.sign(key);
///   assert!(result.is_ok());
/// }
/// ```
#[proc_macro_derive(Sign, attributes(sign))]
pub fn my_macro(input: TokenStream) -> TokenStream {
	// Parse the input tokens into a syntax tree
	let input = parse_macro_input!(input as DeriveInput);

	let name = input.ident;
	let fields = match input.data {
		Data::Struct(data) => data.fields,
		_ => panic!("Sign can only be derived on structs."),
	};

	let generics = add_trait_bounds(input.generics);
	let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

	let filtered_fields: Vec<Field> = fields.clone()
		.into_iter()
		.filter(|field| should_field_be_signed(&field))
		.collect();

	let stripped_fields = filtered_fields.iter().map(|field| {
		let mut new_field = field.clone();
		new_field.attrs = field.attrs.clone().into_iter().filter(|attr| attr.path != SIGN).collect();
		let token_stream = new_field.to_token_stream();
		quote!(
			#token_stream,
		)
	});

	let set_fields = fields
		.iter()
		.filter(|field| !should_field_be_signed(&field))
		.map(|field| {
			let field_name = field.ident.as_ref();
			quote!(
				#field_name,
			)
		});

	let set_filtered_fields = filtered_fields
		.iter()
		.map(|field| {
			let field_name = field.ident.as_ref();
			quote!(
				#field_name: stripped.#field_name,
			)
		});

	let field_names = fields.iter().map(|field| {
		let field_name = field.ident.as_ref();
		quote!(
			#field_name,
		)
	});

	let filtered_field_names = filtered_fields.iter().map(|field| {
		let field_name = field.ident.as_ref();
		quote!(
			#field_name,
		)
	});

	let signature = fields.iter().find(|field| {
		get_sign_attributes(&field).contains(&Attr::Signature)
	}).map(|field| {
		let field_name = field.ident.as_ref();
		quote!(
			#field_name
		)
	}).expect("At least one field needs to be marked as signature");
	// TODO: Also warn if more than one field is marked as signature
	// that only the first one will be used as signature field.

	let expanded = quote!{
		// Stripped down version of struct with only filtered fields
		// and with sign attributes removed from fields
		#[derive(Serialize, Debug, Default)]
		struct Stripped #impl_generics #where_clause {
			#( #stripped_fields )*
		}

		impl #impl_generics Sign for #name #ty_generics #where_clause {

			fn sign(self, key: &str) -> std::result::Result<Self, zerucrypt::Error> {
				Ok(self.sign_with(move |data| zerucrypt::sign(data, key))?)
			}
			fn sign_with<F: FnOnce(Vec<u8>) -> std::result::Result<String, zerucrypt::Error> + Sized>(self, signer: F) -> std::result::Result<Self, zerucrypt::Error> {
				let #name {
					#( #field_names )*
				} = self;

				// TODO: complain if field with name stripped exists
				// Create stripped down structure with filtered fields
				let stripped = Stripped {
					#( #filtered_field_names )*
				};

				let (serialized, mut restored) = (
					// TODO: Remove unwrap here
					serde_json::to_string(&stripped).unwrap(),
					#name {
						#( #set_filtered_fields )*
						#( #set_fields )*
					},
				);

				let signature = signer(serialized.as_bytes().to_vec())?;
				restored.#signature = signature;

				Ok(restored)
			}
		}
	};

	// Hand the output tokens back to the compiler
	TokenStream::from(expanded)
}

fn add_trait_bounds(mut generics: Generics) -> Generics {
	for param in &mut generics.params {
		if let GenericParam::Type(ref mut type_param) = *param {
			type_param.bounds.push(parse_quote!(Serialize));
		}
	}
	generics
}

fn should_field_be_signed(field: &syn::Field) -> bool {
	field.attrs.iter().all(|attr| {
		if attr.path != SIGN {
			return true;
		}

		let meta_items = get_sign_meta_items(&attr);
		return !meta_items.iter().any(|meta_item| {
			match meta_item {
				NestedMeta::Meta(Meta::Path(word)) => word == SKIP || word == SIGNATURE,
				_ => false,
			}
		});
	})
}

fn get_sign_attributes(field: &syn::Field) -> Vec<Attr> {
	field.attrs.iter().map(|attr| {
		let meta_items = get_sign_meta_items(&attr);
		meta_items.iter().map(|meta_item| match meta_item {
			NestedMeta::Meta(Meta::Path(word)) => {
				if word == SKIP {
					Attr::Skip
				} else if word == SIGNATURE {
					Attr::Signature
				} else {
					Attr::Unrecognized
				}
			},
			_ => {
				Attr::Unrecognized
			}
		}).collect::<Vec<_>>()
	}).flatten().collect()
}

fn get_sign_meta_items(attr: &syn::Attribute) -> Vec<syn::NestedMeta> {
	if attr.path != SIGN {
		return Vec::new();
	}

	match attr.parse_meta() {
		Ok(Meta::List(meta)) => meta.nested.into_iter().collect(),
		_ => Vec::new(),
	}
}
