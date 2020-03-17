![Build](http://localhost:43110/1M4Wwi5x5RUN1QJoS6CcnQh515FMtRNg1d/img/build.svg)
![Tests](http://localhost:43110/1M4Wwi5x5RUN1QJoS6CcnQh515FMtRNg1d/img/tests.svg)
![Coverage](http://localhost:43110/1M4Wwi5x5RUN1QJoS6CcnQh515FMtRNg1d/img/coverage.svg)

# ZeruCrypt
A rust cryptography interface for ZeroNet/zerunet.

This library is a part of the zerunet project. It has been split
from the main project because it could be useful to build programs
that have to sign data that ZN clients will consider valid.

## Benchmarks
Zerucrypt has not been benchmarked yet.
If you'd like to help: contact Ansho Rei (anshorei@zeroid.bit) on ZeroMe or ZeroMail!

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

## create

```
use zerucrypt::create;

let (priv_key, pub_key) = create();
```
