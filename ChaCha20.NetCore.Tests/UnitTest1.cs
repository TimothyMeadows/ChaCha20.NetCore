using ChaCha20.NetCore;
using PinnedMemory;

namespace ChaCha20.NetCore.Tests;

public class ChaCha20ValidationTests
{
    [Fact]
    public void Constructor_RejectsNonRfcNonceLength()
    {
        using var key = new PinnedMemory<byte>(new byte[32], false);
        var nonce = new byte[8];

        var exception = Assert.Throws<ArgumentException>(() => new ChaCha20(key, nonce));

        Assert.Contains("96-bit nonce", exception.Message);
    }
}
