using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace DotNetRsaExample
{
    public class NetFxRsaCrypto : IRsaCrypto, IDisposable
    {
        private int KeySize = 1024;
        // Name for MapNameToOID
        // REF: https://learn.microsoft.com/zh-tw/dotnet/api/system.security.cryptography.cryptoconfig?view=net-7.0#remarks
        private string HashAlgorithm = "SHA256";

        private RSACryptoServiceProvider _cspPubKey = null;
        private RSACryptoServiceProvider _cspPrivKey = null;
        RSACryptoServiceProvider CspFromPubKey => _cspPubKey ?? throw new ApplicationException("No public key is set.");
        RSACryptoServiceProvider CspFromPrivKey => _cspPrivKey ?? throw new ApplicationException("No private key is set.");

        public string PubKey
        {
            get => RSAKeys.ExportPublicKey(CspFromPubKey);
            set => _cspPubKey = RSAKeys.ImportPublicKey(value);
        }

        public string PrivKey
        {
            get => RSAKeys.ExportPrivateKey(CspFromPrivKey);
            set => _cspPrivKey = RSAKeys.ImportPrivateKey(value);
        }

        public NetFxRsaCrypto(int? keySize = null, string hashAlgorithm = null!)
        {
            KeySize = keySize ?? KeySize;
            HashAlgorithm = hashAlgorithm ?? HashAlgorithm;
            var csp = new RSACryptoServiceProvider(KeySize);
            _cspPubKey = _cspPrivKey = csp;
        }

        public byte[] Encrypt(byte[] plainData)
            => CspFromPubKey.Encrypt(plainData, false);
        // fOAEP = false, use PKCS#1 v1.5 padding
        // fOAEP = true, use OAEP padding


        public byte[] Decrypt(byte[] cipherData)
            => CspFromPrivKey.Decrypt(cipherData, false);

        public byte[] Sign(byte[] data)
            => CspFromPrivKey.SignData(data, CryptoConfig.MapNameToOID(HashAlgorithm));

        public bool Verify(byte[] data, byte[] signature)
            => CspFromPubKey.VerifyData(data, CryptoConfig.MapNameToOID(HashAlgorithm), signature);
        public void Dispose()
        {
            _cspPrivKey?.Dispose();
            _cspPubKey?.Dispose();
        }
    }
}