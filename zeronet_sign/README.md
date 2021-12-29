# Zeronet Sign
Easily make rust structures signable as ZeroNet content files

```
use serde_derive::{Serialize, Deserialize};
use zeronet_sign::Sign;
use zeronet_sign_derive::*;
use zeronet_cryptography;

pub fn is_default<T: Default + PartialEq>(t: &T) -> bool {
	t == &T::default()
}

#[derive(Serialize, Deserialize, Sign, Default)]
struct MyStruct {
	data: String,
	#[serde(skip_serializing_if = "is_default")]
	#[sign(signature)]
	sign: String,
	#[sign(skip)]
	skipped_field: bool,
}

fn main () {
	let mut my_struct = MyStruct {
		data: "random_data".to_string(),
		sign: String::new(),
		skipped_field: true,
	};

	let key = "5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss";
	let result = my_struct.sign(key);

  assert!(result.is_ok());
}
```
