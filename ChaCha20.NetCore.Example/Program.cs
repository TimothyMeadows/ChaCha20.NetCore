using System;
using System.Security.Cryptography;
using PinnedMemory;

namespace ChaCha20.NetCore.Example
{
    class Program
    {
        static void Main(string[] args)
        {
            var iv = new byte[16];
            var key = new byte[32];

            using var provider = new RNGCryptoServiceProvider();
            provider.GetBytes(iv);
            provider.GetBytes(key);

            using var keyPin = new PinnedMemory<byte>(key, false);
            using var cipher = new ChaCha20(keyPin, iv);
            cipher.UpdateBlock(new PinnedMemory<byte>(new byte[] {63, 61, 77, 20, 63, 61, 77, 20, 63, 61, 77}, false),
                0, 11); // caw caw caw in utf8

            using var output = new PinnedMemory<byte>(new byte[cipher.GetLength()]);
            cipher.DoFinal(output, 0);

            Console.WriteLine(BitConverter.ToString(output.ToArray()));
        }
    }
}
