using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

namespace DotNetRsaExample
{
    public class BCRsaCrypto : IRsaCrypto, IDisposable
    {
        private int KeySize = 1024;
        private string HashAlgorithm = "SHA-256withRSA";
        private string CipherSuite = "RSA/ECB/PKCS1Padding";

        AsymmetricKeyParameter _asymKeyParam = null;
        AsymmetricCipherKeyPair _asymCipherKeyPair = null;
        private string _pubKey = null;
        private string _privKey = null;
        AsymmetricKeyParameter AsymKeyParam => _asymKeyParam ?? throw new ApplicationException("No public key is set.");
        AsymmetricCipherKeyPair AsymCipherKeyPair => _asymCipherKeyPair ?? throw new ApplicationException("No private key is set.");

        public string PubKey
        {
            get => _pubKey;
            private set
            {
                var pubKeyReader = new StringReader(value);
                var pemReader = new PemReader(pubKeyReader);
                _asymKeyParam = (AsymmetricKeyParameter)pemReader.ReadObject();
                _pubKey = value;
            }
        }

        public string PrivKey
        {
            get => _privKey;
            private set
            {
                var privKeyReader = new StringReader(value);
                var pemReader = new PemReader(privKeyReader);
                _asymCipherKeyPair = (AsymmetricCipherKeyPair)pemReader.ReadObject();
                _privKey = value;
            }
        }

        public BCRsaCrypto(int? keySize = null, string hashAlgorithm = null!, string cipherSuite = null!)
        {
            KeySize = keySize ?? KeySize;
            HashAlgorithm = hashAlgorithm ?? HashAlgorithm;
            CipherSuite = cipherSuite ?? CipherSuite;
            (PubKey, PrivKey) = GenerateKeyPair();
        }

        public BCRsaCrypto(string pubKey, string privKey, string hashAlgorithm = null!, string cipherSuite = null!)
        {
            HashAlgorithm = hashAlgorithm ?? HashAlgorithm;
            CipherSuite = cipherSuite ?? CipherSuite;
            if (!string.IsNullOrEmpty(pubKey)) PubKey = pubKey;
            if (!string.IsNullOrEmpty(privKey)) PrivKey = privKey;
        }

        public static BCRsaCrypto FromPubKey(string pubKey, string hashAlgorithm = null!, string cipherSuite = null!)
            => new BCRsaCrypto(pubKey, null!, hashAlgorithm, cipherSuite);

        public static BCRsaCrypto FromPrivKey(string privKey, string hashAlgorithm = null!, string cipherSuite = null!)
            => new BCRsaCrypto(null!, privKey, hashAlgorithm, cipherSuite);
        

        (string pubKey, string privKey) GenerateKeyPair()
        {
            var keyGen = new RsaKeyPairGenerator();
            keyGen.Init(new KeyGenerationParameters(new SecureRandom(), KeySize));
            var keyPair = keyGen.GenerateKeyPair();

            Func<AsymmetricKeyParameter, string> writeKey = (key) =>
            {
                var sw = new StringWriter();
                var pemWriter = new PemWriter(sw);
                pemWriter.WriteObject(key);
                pemWriter.Writer.Flush();
                return sw.ToString();
            };

            var pubKey = writeKey(keyPair.Public);
            var privKey = writeKey(keyPair.Private);
            return (pubKey, privKey);
        }

        public byte[] Encrypt(byte[] plainData)
        {
            var cipher = CipherUtilities.GetCipher(CipherSuite);
            cipher.Init(true, AsymKeyParam);
            return cipher.DoFinal(plainData);
        }

        public byte[] Decrypt(byte[] cipherData)
        {
            var cipher = CipherUtilities.GetCipher(CipherSuite);
            cipher.Init(false, AsymCipherKeyPair.Private);
            return cipher.DoFinal(cipherData);
        }

        public byte[] Sign(byte[] data)
        {
            var signer = SignerUtilities.GetSigner(HashAlgorithm);
            signer.Init(true, AsymCipherKeyPair.Private);
            signer.BlockUpdate(data, 0, data.Length);
            return signer.GenerateSignature();
        }

        public bool Verify(byte[] data, byte[] signature)
        {
            var signer = SignerUtilities.GetSigner(HashAlgorithm);
            signer.Init(false, AsymKeyParam);
            signer.BlockUpdate(data, 0, data.Length);
            return signer.VerifySignature(signature);
        }

        public void Dispose()
        {
        }
    }
}