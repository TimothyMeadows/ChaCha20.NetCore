using System.Security.Cryptography;
using PinnedMemory;

namespace ChaCha20.NetCore.Example;

internal static class Program
{
    private static void Main(string[] args)
    {
        var nonce = RandomNumberGenerator.GetBytes(12);
        var key = RandomNumberGenerator.GetBytes(32);
        var message = new byte[] { 63, 61, 77, 20, 63, 61, 77, 20, 63, 61, 77 }; // caw caw caw in utf8

        using var keyPin = new PinnedMemory<byte>(key, false);
        using var cipher = new ChaCha20(keyPin, nonce);
        using var messagePin = new PinnedMemory<byte>(message, false);

        cipher.UpdateBlock(messagePin, 0, message.Length);

        using var output = new PinnedMemory<byte>(new byte[cipher.GetLength()]);
        cipher.DoFinal(output, 0);

        Console.WriteLine(BitConverter.ToString(output.ToArray()));
        CryptographicOperations.ZeroMemory(key);
    }
}
