using System.Globalization;
using ChaCha20.NetCore;
using PinnedMemory;

namespace ChaCha20.NetCore.Tests;

public class ChaCha20Rfc8439Tests
{
    [Fact]
    public void Rfc8439_BlockFunction_Vector_MatchesForCounterOne()
    {
        var key = HexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        var nonce = HexToBytes("000000090000004a00000000");
        var expectedBlockOne = HexToBytes(
            "10f1e7e4d13b5915500fdd1fa32071c4" +
            "c7d1f4c733c068030422aa9ac3d46c4e" +
            "d2826446079faa0914c2d705d98b02a2" +
            "b5129cd1de164eb9cbd083e8a2503c4e");

        using var keyPin = new PinnedMemory<byte>(key, false);
        using var cipher = new ChaCha20(keyPin, nonce);

        var plaintext = new byte[128];
        var output = new byte[128];
        cipher.UpdateBlock(plaintext, 0, plaintext.Length);
        cipher.DoFinal(output, 0);

        Assert.Equal(expectedBlockOne, output[64..128]);
    }

    [Fact]
    public void Rfc8439_Encryption_Vector_MatchesForCounterOne()
    {
        var key = HexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        var nonce = HexToBytes("000000000000004a00000000");
        var plaintext = HexToBytes(
            "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a20" +
            "4966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f722074686520" +
            "6675747572652c2073756e73637265656e20776f756c642062652069742e");
        var expectedCiphertext = HexToBytes(
            "6e2e359a2568f98041ba0728dd0d6981" +
            "e97e7aec1d4360c20a27afccfd9fae0b" +
            "f91b65c5524733ab8f593dabcd62b357" +
            "1639d624e65152ab8f530c359f0861d8" +
            "07ca0dbf500d6a6156a38e088a22b65e" +
            "52bc514d16ccf806818ce91ab7793736" +
            "5af90bbf74a35be6b40b8eedf2785e42" +
            "874d");

        var prefixedPlaintext = new byte[64 + plaintext.Length];
        Buffer.BlockCopy(plaintext, 0, prefixedPlaintext, 64, plaintext.Length);

        using var keyPin = new PinnedMemory<byte>(key, false);
        using var cipher = new ChaCha20(keyPin, nonce);

        var output = new byte[prefixedPlaintext.Length];
        cipher.UpdateBlock(prefixedPlaintext, 0, prefixedPlaintext.Length);
        cipher.DoFinal(output, 0);

        Assert.Equal(expectedCiphertext, output[64..]);
    }

    [Fact]
    public void Rfc8439_EncryptionAndDecryption_RoundTrip_WithByteArrayApi()
    {
        var key = HexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        var nonce = HexToBytes("000000000000004a00000000");
        var plaintext = HexToBytes(
            "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a20" +
            "4966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f722074686520" +
            "6675747572652c2073756e73637265656e20776f756c642062652069742e");

        var prefixedPlaintext = new byte[64 + plaintext.Length];
        Buffer.BlockCopy(plaintext, 0, prefixedPlaintext, 64, plaintext.Length);

        using var encryptKeyPin = new PinnedMemory<byte>(key, false);
        using var encryptor = new ChaCha20(encryptKeyPin, nonce);

        var ciphertext = new byte[prefixedPlaintext.Length];
        encryptor.UpdateBlock(prefixedPlaintext, 0, prefixedPlaintext.Length);
        encryptor.DoFinal(ciphertext, 0);

        using var decryptKeyPin = new PinnedMemory<byte>(key, false);
        using var decryptor = new ChaCha20(decryptKeyPin, nonce);

        var decrypted = new byte[ciphertext.Length];
        decryptor.UpdateBlock(ciphertext, 0, ciphertext.Length);
        decryptor.DoFinal(decrypted, 0);

        Assert.Equal(prefixedPlaintext, decrypted);
    }

    private static byte[] HexToBytes(string hex)
    {
        if (hex.Length % 2 != 0)
        {
            throw new ArgumentException("Hex string must have an even length.", nameof(hex));
        }

        var bytes = new byte[hex.Length / 2];
        for (var i = 0; i < bytes.Length; i++)
        {
            bytes[i] = byte.Parse(hex.AsSpan(i * 2, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture);
        }

        return bytes;
    }
}
