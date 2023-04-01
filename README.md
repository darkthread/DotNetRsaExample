# DotNetRsaExample

RSA public-private key encryption and decryption and digital signature .NET program example. 

The example is about using RSACryptoServiceProvider in .NET Framework and BouncyCastle open-source library in new .NET projects. The public and private keys are exportable in PEM format for easy exchange and saving. The goal is to make RSACryptoServiceProvider and BouncyCastle interoperable so that they can decrypt each other’s encrypted content and verify each other’s digital signatures.

[Blog post](https://blog.darkthread.net/blog/dotnet-rsa-example/) 

Usage:

```cs
IRsaCrypto crypto = new NetFxRsaCrypto();
var pubKey = crypto.PubKey;
var privKey = crypto.PrivKey;
var plainText = "Hello, World!";
var plainData = Encoding.UTF8.GetBytes(plainText);
var cipherData = crypto.Encrypt(plainData);
var decryptedData = crypto.Decrypt(cipherData);
var signature = crypto.Sign(plainData);
var verified = crypto.Verify(plainData, signature);
IRsaCrypto bcCrypto = new BCRsaCrypto(pubKey, privKey);
var verfiedByBC = bcCrypto.Verify(plainData, signature);
```
