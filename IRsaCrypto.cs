namespace DotNetRsaExample
{
    public interface IRsaCrypto
    {
        string PubKey { get;  }
        string PrivKey { get; }
        byte[] Encrypt(byte[] plainData);
        bool Verify(byte[] data, byte[] signature);
        byte[] Decrypt(byte[] cipherData);
        byte[] Sign(byte[] data);
    }
}