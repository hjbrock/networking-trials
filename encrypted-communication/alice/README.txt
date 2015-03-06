-----------------------------------------------
Alice Program ReadMe
-----------------------------------------------
To compile the Alice program run:
javac -d . src/hbrock/alice/*.java

To run the Alice program, you must first generate the keys needed
by Alice. Some of these keys have counterparts that are required
by Bob. The keys required are:

Alice's private key
Third party public key

Additionally, these keys must be in DER format.

To get a key pair in DER format, you can use the openssl commandline:
openssl genpkey -out alice_priv.der -outform DER -algorithm RSA rsa_keygen_bits:4096
openssl rsa -in alice_priv.der -out alive_pub.der -inform DER -outform DER -pubout

To convert a key pair that's in PEM format, you can do:
openssl pkcs8 -topk8 -inform PEM -outform DER -in alice_priv.pem -out alice_priv.der -nocrypt
openssl rsa -pubin -in alice_pub.pem -outform DER -out alice_pub.der

After generating the keys (or if you're going to use the default keys), start the Bob 
program first, then run Alice via:
java hbrock.alice.Alice [options]

Options:
-bobHost <host> REQUIRED. Hostname where the Bob program is running
-bobPort <port> REQUIRED. Port Bob is running on
-msg <file>     OPTIONAL. File containing message to send. Defaults to console input.
-v              OPTIONAL. Use this option for verbose output
-privKey <file> OPTIONAL. Specify Alice's private key file. Defaults to 'alice_priv.der'
-veriKey <file> OPTIONAL. Specify the third party verification public key file. Defaults
                          to 'verification_pub.der'
