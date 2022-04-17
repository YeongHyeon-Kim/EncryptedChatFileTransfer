## Introduction

-   Problem
-   What I did
-   What I changed
-   Precautions when running the program

### Problem

I implemented RSA key exchange, encrypted message transfer using AES key exchange, and encrypted file transfer including signature.

### What I did

Overall, server and client communication was implemented using Java socket communication.

1. RSA key generation - A public key and a private key are generated.
2. Save RSA key - You can save it as 'PublicKey.key' and 'PrivateKey.key' in any location.
3. RSA key exchange - The public key is converted into simple bytes before transmission, and the private key is not exchanged.
4. AES Key Exchange - For AES key exchange, the server first transmits the public key to the client, and the client generates the AES key, encrypts it using the received public key, and sends it to the server. The server decrypts the received encrypted AES key using the previously created private key to obtain the AES key.
5. Message transmission - The message is encrypted and transmitted using the exchanged AES key.
6. Message Decryption - Decrypts the received encrypted message using the AES key.
7. File transfer - The file is encrypted using the exchanged AES key, and a signature is created using the received public key and transmitted together.
8. File Decryption - Verifies the received signature using the stored Private key, and if it is determined that the sender is correct, the received encrypted file is decrypted using the AES key.
9. Save File - You can save the decrypted file in a desired location with a desired name.

### What I Changed

1. When an input is received during communication connection, receiver do not know what kind of input it is, so I used JSONObject and sent it including the header.
2. In file transfer, the file name is encrypted using an AES key and transmitted.
3. The current key exchange state was determined by using the connectionState variable.
4. When connectionState is
   1 : The RSA key has not been generated yet.
   2 : The RSA key has been generated and can be sent.
   3 : AES key was sent or received. message transmission is possible.
   4 : Received or sent a public key.
   5 : If the public key is received when the connectionState is 3 or the AES key is received when the connectionState is 4, the signautre can be created and file transfer is possible.

### Precautions when running the program

4.1. You must proceed in English mode using the Korean/English keys. When running the program in Korean mode, this error may occur.
'Terminating app due to uncaught exception 'NSInvalidArgumentException', reason: '+[AWTView keyboardInputSourceChanged:]: unrecognized selector sent to class 0x1056323b8''

4.2. If JSONObject library is not installed
please add JSONObject library
