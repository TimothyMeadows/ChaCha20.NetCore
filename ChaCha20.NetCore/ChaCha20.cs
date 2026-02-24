using System;
using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using PinnedMemory;

namespace ChaCha20.NetCore;

/*
 * This code was adapted from BouncyCastle 1.8.3 ChaChaEngine.cs
 * you can read more about ChaCha20 here: https://cr.yp.to/chacha/chacha-20080128.pdf
 */

/// <summary>
/// Implementation of Daniel J. Bernstein's ChaCha20 stream cipher.
/// Defaults to RFC 8439 conventions (256-bit key, 96-bit nonce, 32-bit counter).
/// </summary>
public sealed class ChaCha20 : IDisposable
{
    private const int StateSize = 16;
    private const int KeyLengthInBytes = 32;
    private const int RfcNonceLengthInBytes = 12;

    private static readonly uint[] Sigma = LE_To_UInt32(Encoding.ASCII.GetBytes("expand 32-byte k"), 0, 4);

    private readonly byte[] _keyStream = new byte[StateSize * 4];
    private readonly PinnedMemory<byte> _keyStreamPin;
    private readonly uint[] _engineState = new uint[StateSize];
    private readonly PinnedMemory<uint> _engineStatePin;
    private readonly uint[] _x = new uint[StateSize];
    private readonly PinnedMemory<uint> _xPin;
    private byte[] _buffer = [];

    private int _index;
    private uint _cW0;
    private uint _cW1;
    private uint _cW2;
    private bool _disposed;

    public int Rounds { get; }

    /// <summary>
    /// Creates a ChaCha20 engine using RFC 8439 parameters.
    /// </summary>
    public ChaCha20(PinnedMemory<byte> key, byte[] nonce, int rounds = 20)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(nonce);

        if (rounds <= 0 || (rounds & 1) != 0)
        {
            throw new ArgumentOutOfRangeException(nameof(rounds), "Number of rounds must be positive and even.");
        }

        _keyStreamPin = new PinnedMemory<byte>(_keyStream);
        _engineStatePin = new PinnedMemory<uint>(_engineState);
        _xPin = new PinnedMemory<uint>(_x);

        Rounds = rounds;
        SetKey(key, nonce);
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        Reset();
        CryptographicOperations.ZeroMemory(_keyStream);
        Array.Clear(_engineState);
        Array.Clear(_x);

        _keyStreamPin.Dispose();
        _engineStatePin.Dispose();
        _xPin.Dispose();
        _disposed = true;
    }

    public int GetLength() => _buffer.Length;

    public byte[] GetBuffer()
    {
        return _buffer.Length == 0 ? [] : (byte[])_buffer.Clone();
    }

    public void Update(byte value)
    {
        EnsureNotDisposed();
        var expanded = ArrayPool<byte>.Shared.Rent(_buffer.Length + 1);

        try
        {
            _buffer.AsSpan().CopyTo(expanded);
            expanded[_buffer.Length] = value;
            _buffer = expanded[..(_buffer.Length + 1)].ToArray();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(expanded);
            ArrayPool<byte>.Shared.Return(expanded);
        }
    }

    public void UpdateBlock(byte[] value, int offset, int length)
    {
        ArgumentNullException.ThrowIfNull(value);
        EnsureNotDisposed();
        ValidateRange(value.Length, offset, length, "input buffer too short");
        AppendToBuffer(value.AsSpan(offset, length));
    }

    public void UpdateBlock(PinnedMemory<byte> value, int offset, int length)
    {
        ArgumentNullException.ThrowIfNull(value);
        EnsureNotDisposed();
        ValidateRange(value.Length, offset, length, "input buffer too short");

        var block = value.ToArray();
        try
        {
            AppendToBuffer(block.AsSpan(offset, length));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(block);
        }
    }

    public void DoFinal(PinnedMemory<byte> output, int offset)
    {
        ArgumentNullException.ThrowIfNull(output);
        EnsureNotDisposed();
        OutputLength(output.Length, offset, _buffer.Length, "output buffer too short");
        ProcessBuffer((i, b) => output[i + offset] = b);
    }

    public void DoFinal(byte[] output, int offset)
    {
        ArgumentNullException.ThrowIfNull(output);
        EnsureNotDisposed();
        OutputLength(output.Length, offset, _buffer.Length, "output buffer too short");
        ProcessBuffer((i, b) => output[i + offset] = b);
    }

    public void Reset()
    {
        EnsureNotDisposed();
        _index = 0;
        ResetLimitCounter();
        ResetCounter();
        CryptographicOperations.ZeroMemory(_buffer);
        _buffer = [];
    }

    private void AppendToBuffer(ReadOnlySpan<byte> source)
    {
        var expanded = new byte[_buffer.Length + source.Length];
        _buffer.AsSpan().CopyTo(expanded);
        source.CopyTo(expanded.AsSpan(_buffer.Length));
        CryptographicOperations.ZeroMemory(_buffer);
        _buffer = expanded;
    }

    private void ProcessBuffer(Action<int, byte> writeOutput)
    {
        if (LimitExceeded((uint)_buffer.Length))
        {
            throw new InvalidOperationException("2^70 byte limit per nonce would be exceeded; change nonce.");
        }

        for (var i = 0; i < _buffer.Length; i++)
        {
            if (_index == 0)
            {
                GenerateKeyStream(_keyStream);
                AdvanceCounter();
            }

            writeOutput(i, (byte)(_keyStream[_index] ^ _buffer[i]));
            _index = (_index + 1) & 63;
        }
    }

    private static uint RotateLeft(uint x, int y) => (x << y) | (x >> (32 - y));

    private void ResetLimitCounter()
    {
        _cW0 = 0;
        _cW1 = 0;
        _cW2 = 0;
    }

    private bool LimitExceeded(uint len)
    {
        var old = _cW0;
        _cW0 += len;
        if (_cW0 < old && ++_cW1 == 0)
        {
            return (++_cW2 & 0x20) != 0;
        }

        return false;
    }

    private static void ValidateRange(int bufferLength, int offset, int length, string message)
    {
        if (offset < 0 || length < 0 || offset > bufferLength - length)
        {
            throw new ArgumentOutOfRangeException(nameof(offset), message);
        }
    }

    private static void OutputLength(int bufferLength, int offset, int length, string message)
    {
        if (offset < 0 || length < 0 || offset > bufferLength - length)
        {
            throw new ArgumentOutOfRangeException(nameof(offset), message);
        }
    }

    internal static void UInt32_To_LE(uint n, byte[] bs, int off)
    {
        bs[off] = (byte)n;
        bs[off + 1] = (byte)(n >> 8);
        bs[off + 2] = (byte)(n >> 16);
        bs[off + 3] = (byte)(n >> 24);
    }

    internal static void UInt32_To_LE(uint[] ns, byte[] bs, int off)
    {
        foreach (var n in ns)
        {
            UInt32_To_LE(n, bs, off);
            off += 4;
        }
    }

    internal static uint LE_To_UInt32(PinnedMemory<byte> bs, int off)
    {
        return bs[off]
               | ((uint)bs[off + 1] << 8)
               | ((uint)bs[off + 2] << 16)
               | ((uint)bs[off + 3] << 24);
    }

    internal static uint LE_To_UInt32(byte[] bs, int off)
    {
        return (uint)bs[off]
               | ((uint)bs[off + 1] << 8)
               | ((uint)bs[off + 2] << 16)
               | ((uint)bs[off + 3] << 24);
    }

    internal static void LE_To_UInt32(PinnedMemory<byte> bs, int bOff, uint[] ns, int nOff, int count)
    {
        for (var i = 0; i < count; ++i)
        {
            ns[nOff + i] = LE_To_UInt32(bs, bOff);
            bOff += 4;
        }
    }

    internal static void LE_To_UInt32(byte[] bs, int bOff, uint[] ns, int nOff, int count)
    {
        for (var i = 0; i < count; ++i)
        {
            ns[nOff + i] = LE_To_UInt32(bs, bOff);
            bOff += 4;
        }
    }

    internal static uint[] LE_To_UInt32(byte[] bs, int off, int count)
    {
        var ns = new uint[count];
        for (var i = 0; i < ns.Length; ++i)
        {
            ns[i] = LE_To_UInt32(bs, off);
            off += 4;
        }

        return ns;
    }

    private void AdvanceCounter()
    {
        if (++_engineState[12] == 0)
        {
            throw new InvalidOperationException("ChaCha20 block counter overflowed; change nonce.");
        }
    }

    private void ResetCounter() => _engineState[12] = 0;

    private void SetKey(PinnedMemory<byte> keyBytes, byte[] nonceBytes)
    {
        if (keyBytes.Length != KeyLengthInBytes)
        {
            throw new ArgumentException("ChaCha20 requires a 256-bit key.", nameof(keyBytes));
        }

        if (nonceBytes.Length != RfcNonceLengthInBytes)
        {
            throw new ArgumentException("ChaCha20 requires a 96-bit nonce per RFC 8439.", nameof(nonceBytes));
        }

        _engineState[0] = Sigma[0];
        _engineState[1] = Sigma[1];
        _engineState[2] = Sigma[2];
        _engineState[3] = Sigma[3];

        LE_To_UInt32(keyBytes, 0, _engineState, 4, 8);
        _engineState[12] = 0;
        LE_To_UInt32(nonceBytes, 0, _engineState, 13, 3);
    }

    private void GenerateKeyStream(byte[] output)
    {
        ChachaCore(Rounds, _engineState, _x);
        UInt32_To_LE(_x, output, 0);
    }

    private static void ChachaCore(int rounds, uint[] input, uint[] x)
    {
        if (input.Length != StateSize || x.Length != StateSize)
        {
            throw new ArgumentException("input and x must be 16 words.");
        }

        if ((rounds & 1) != 0)
        {
            throw new ArgumentException("Number of rounds must be even", nameof(rounds));
        }

        var x00 = input[0];
        var x01 = input[1];
        var x02 = input[2];
        var x03 = input[3];
        var x04 = input[4];
        var x05 = input[5];
        var x06 = input[6];
        var x07 = input[7];
        var x08 = input[8];
        var x09 = input[9];
        var x10 = input[10];
        var x11 = input[11];
        var x12 = input[12];
        var x13 = input[13];
        var x14 = input[14];
        var x15 = input[15];

        for (var i = rounds; i > 0; i -= 2)
        {
            x00 += x04; x12 = RotateLeft(x12 ^ x00, 16);
            x08 += x12; x04 = RotateLeft(x04 ^ x08, 12);
            x00 += x04; x12 = RotateLeft(x12 ^ x00, 8);
            x08 += x12; x04 = RotateLeft(x04 ^ x08, 7);
            x01 += x05; x13 = RotateLeft(x13 ^ x01, 16);
            x09 += x13; x05 = RotateLeft(x05 ^ x09, 12);
            x01 += x05; x13 = RotateLeft(x13 ^ x01, 8);
            x09 += x13; x05 = RotateLeft(x05 ^ x09, 7);
            x02 += x06; x14 = RotateLeft(x14 ^ x02, 16);
            x10 += x14; x06 = RotateLeft(x06 ^ x10, 12);
            x02 += x06; x14 = RotateLeft(x14 ^ x02, 8);
            x10 += x14; x06 = RotateLeft(x06 ^ x10, 7);
            x03 += x07; x15 = RotateLeft(x15 ^ x03, 16);
            x11 += x15; x07 = RotateLeft(x07 ^ x11, 12);
            x03 += x07; x15 = RotateLeft(x15 ^ x03, 8);
            x11 += x15; x07 = RotateLeft(x07 ^ x11, 7);
            x00 += x05; x15 = RotateLeft(x15 ^ x00, 16);
            x10 += x15; x05 = RotateLeft(x05 ^ x10, 12);
            x00 += x05; x15 = RotateLeft(x15 ^ x00, 8);
            x10 += x15; x05 = RotateLeft(x05 ^ x10, 7);
            x01 += x06; x12 = RotateLeft(x12 ^ x01, 16);
            x11 += x12; x06 = RotateLeft(x06 ^ x11, 12);
            x01 += x06; x12 = RotateLeft(x12 ^ x01, 8);
            x11 += x12; x06 = RotateLeft(x06 ^ x11, 7);
            x02 += x07; x13 = RotateLeft(x13 ^ x02, 16);
            x08 += x13; x07 = RotateLeft(x07 ^ x08, 12);
            x02 += x07; x13 = RotateLeft(x13 ^ x02, 8);
            x08 += x13; x07 = RotateLeft(x07 ^ x08, 7);
            x03 += x04; x14 = RotateLeft(x14 ^ x03, 16);
            x09 += x14; x04 = RotateLeft(x04 ^ x09, 12);
            x03 += x04; x14 = RotateLeft(x14 ^ x03, 8);
            x09 += x14; x04 = RotateLeft(x04 ^ x09, 7);
        }

        x[0] = x00 + input[0];
        x[1] = x01 + input[1];
        x[2] = x02 + input[2];
        x[3] = x03 + input[3];
        x[4] = x04 + input[4];
        x[5] = x05 + input[5];
        x[6] = x06 + input[6];
        x[7] = x07 + input[7];
        x[8] = x08 + input[8];
        x[9] = x09 + input[9];
        x[10] = x10 + input[10];
        x[11] = x11 + input[11];
        x[12] = x12 + input[12];
        x[13] = x13 + input[13];
        x[14] = x14 + input[14];
        x[15] = x15 + input[15];
    }

    private void EnsureNotDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
    }
}
