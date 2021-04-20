# go-pfx-decode

A minimal implementation in go to extract private key and cert from a pkcs12 password protected
file and export them as pem files.

A pkcs12 file usually has the .pfx or .p12 extensions.

## Compile

    go build .

## Running

    ./pfx-decode -in my-pfx-file.pfx -pass pfx-password


