# ZeruCrypt
A rust cryptography interface for ZeroNet/zerunet.

## verify

```
use zerucrypt::verify;

let data = "Testmessage";
let address = "1HZwkjkeaoZfTSaJxDw6aKkxp45agDiEzN";
let signature = "G+Hnv6dXxOAmtCj8MwQrOh5m5bV9QrmQi7DSGKiRGm9TWqWP3c5uYxUI/C/c+m9+LtYO26GbVnvuwu7hVPpUdow=";

match verify(data, address, signature) {
	Ok(_) => println!("Signature is a valid."),
	Err(_) => println!("Signature is invalid."),
}
```

## sign

```
use zerucrypt::sign;

let data = "Testmessage";
let private_key = "5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss";

match sign(data, private_key) {
	Ok(signature) => println!("The signature is {}", signature),
	Err(_) => println!("An error occured during the signing process"),
}
```