namespace DotNetRsaExample
{
    public interface IRsaCrypto
    {
        string PubKey { get; set; }
        string PrivKey { get; set; }
        byte[] Encrypt(byte[] plainData);
        bool Verify(byte[] data, byte[] signature);
        byte[] Decrypt(byte[] cipherData);
        byte[] Sign(byte[] data);
    }
}