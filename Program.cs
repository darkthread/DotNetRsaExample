
using System.Text;
using DotNetRsaExample;

Action<IRsaCrypto> RunTest = (crypto) =>
{
    Print(crypto.GetType().Name, ConsoleColor.Yellow);
    Print("加解密測試", ConsoleColor.Cyan);
    var plainText = "Hello, World!";
    var plainData = Encoding.UTF8.GetBytes(plainText);
    Console.WriteLine($"明文: {plainText}");
    byte[] cipherData = null!;
    for (var i = 0; i < 2; i++)
    {
        // PKCS#1 / OAEP 加密時會填充一些亂數，故每次加密結果不會相同
        // https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Padding_schemes
        cipherData = crypto.Encrypt(plainData);
        Console.WriteLine($"密文[{i}]: {Convert.ToBase64String(cipherData)}");
        var decryptedData = crypto.Decrypt(cipherData);
        Console.WriteLine($"解密[{i}]：{Encoding.UTF8.GetString(decryptedData)}");
    }
    Print("簽章測試", ConsoleColor.Cyan);
    for (var i = 0; i < 2; i++)
    {
        Console.WriteLine($"資料[{i}]：{plainText}");
        var signature = crypto.Sign(plainData);
        Console.WriteLine($"簽章[{i}]: {Convert.ToBase64String(signature)}");
        var verified = crypto.Verify(plainData, signature);
        Console.WriteLine($"驗證[{i}]: {(verified ? "PASS" : "FAIL")}");
    }
};

var fxRsaCrypto = new NetFxRsaCrypto();
RunTest(fxRsaCrypto);
var bcRsaCrypto = new BCRsaCrypto();
RunTest(bcRsaCrypto);

// 使用既有 PubKey 及 PrivKey 建立 BouncyCastle 的 IRsaCrypto 實作
var bcRsaCryptoSameKey = new BCRsaCrypto(fxRsaCrypto.PubKey, fxRsaCrypto.PrivKey);

Print("交叉加解密", ConsoleColor.Magenta);
string plainText = "由System.Security加密，BouncyCastle解密";
Print($"明文: {plainText}");
var enc = fxRsaCrypto.Encrypt(Encoding.UTF8.GetBytes(plainText));
Print($"密文: {Convert.ToBase64String(enc)}");
Print($"解密: {Encoding.UTF8.GetString(bcRsaCryptoSameKey.Decrypt(enc))}");
Print("交叉簽章", ConsoleColor.Magenta);
var sign = fxRsaCrypto.Sign(Encoding.UTF8.GetBytes(plainText));
Print($"簽章: {Convert.ToBase64String(sign)}");
Print($"驗證: {(bcRsaCryptoSameKey.Verify(Encoding.UTF8.GetBytes(plainText), sign) ? "PASS" : "FAIL")}");

void Print(string msg, ConsoleColor color = ConsoleColor.White)
{
    Console.ForegroundColor = color;
    Console.WriteLine(msg);
    Console.ResetColor();
}



