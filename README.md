# Cryptr-Emulating-Secure-File-Sharing
## This is the project from 419 Computer Security class

### Compile
##### javac Cryptr.java

### You need to generate a file to compile
##### echo "This is a test file" > foo.txt
#
##### java Cryptr generatekey secret.key
##### java Cryptr encryptfile foo.txt secret.key foo.enc
##### openssl genrsa -out private_key.pem 2048
##### openssl pkcs8 -topk8 -inform PEM -outform DER -in private_key.pem -out private_key.der -nocrypt
##### openssl rsa -in private_key.pem -pubout -outform DER -out public_key.der
##### java Cryptr encryptkey secret.key public_key.der s.enckey
##### java Cryptr decryptkey s.enckey private_key.der recovered-secret.key
##### java Cryptr decryptfile foo.enc recovered-secret.key recovered-foo.txt
##### cat recovered-foo.txt
