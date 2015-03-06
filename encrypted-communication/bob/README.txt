-----------------------------------------------
Bob Program ReadMe
-----------------------------------------------
To compile the Bob program run:
javac -d . src/hbrock/bob/*.java

To run the Bob program, you must first generate the keys needed
by Bob. Some of these keys have counterparts that are required
by bob. The keys required are:

bob's public key
Third party private key
Bob's public key
Bob's private key

Additionally, these keys must be in DER format (Java only supports
DER natively).

To get a key pair in DER format, you can use the openssl commandline:
openssl genpkey -out bob_priv.der -outform DER -algorithm RSA rsa_keygen_bits:4096
openssl rsa -in bob_priv.der -out alive_pub.der -inform DER -outform DER -pubout

To convert a key pair that's in PEM format, you can do:
openssl pkcs8 -topk8 -inform PEM -outform DER -in bob_priv.pem -out bob_priv.der -nocrypt
openssl rsa -pubin -in bob_pub.pem -outform DER -out bob_pub.der

After generating the keys (or if you're going to use the default keys), run bob via;
java hbrock.bob.Bob [options]

Options:
-port <port>     REQUIRED. Specify the port Bob should run on
-v               OPTIONAL. Use this option for verbose output
-pubKey <file>   OPTIONAL. Specify Bob's public key file. Defaults to 'bob_pub.der'
-privKey <file>  OPTIONAL. Specify Bob's private key file. Defaults to 'bob_priv.der'
-veriKey <file>  OPTIONAL. Specify the third party verification private key file.
                           Defaults to 'verification_priv.der'
-aliceKey <file> OPTIONAL. Specify Alice's public key file. Defaults to 'alice_pub.der'
