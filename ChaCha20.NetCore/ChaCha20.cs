using System;
using System.Text;
using PinnedMemory;

namespace ChaCha20.NetCore
{
    /*
     * This code was adapted from BouncyCastle 1.8.3 ChaChaEngine.cs
     * you can read more about ChaCha20 here: https://cr.yp.to/chacha/chacha-20080128.pdf
     */

    /// <summary>
    ///     Implementation of Daniel J. Bernstein's ChaCha20 stream cipher.
    /// </summary>
    public class ChaCha20 : IDisposable
    {
        /**
         * Constants
         */
        private const int StateSize = 16; // 16, 32 bit ints = 64 bytes

        private static readonly uint[] TauSigma =
            LE_To_UInt32(Encoding.ASCII.GetBytes("expand 16-byte k" + "expand 32-byte k"), 0, 8);

        private readonly PinnedMemory<byte> _bufferPin;
        private readonly byte[] _keyStream = new byte[StateSize * 4]; // expanded state, 64 bytes
        private readonly PinnedMemory<byte> _keyStreamPin;
        private readonly uint[] _engineState = new uint[StateSize]; // state
        private readonly PinnedMemory<uint> _engineStatePin;
        private readonly PinnedMemory<uint> _xPin;
        private byte[] _buffer = new byte[1];

        /*
         * variables to hold the state of the engine
         * during encryption and decryption
         */
        private int _index;

        /*
         * internal counter
         */
        private uint _cW0, _cW1, _cW2;

        protected int Rounds;
        private readonly uint[] _x = new uint[StateSize]; // internal buffer

        /// <summary>
        ///     Creates a Salsa20 engine with a specific number of rounds.
        /// </summary>
        /// <param name="key"></param>
        /// <param name="iv"></param>
        public ChaCha20(PinnedMemory<byte> key, byte[] iv, int rounds = 20)
        {
            _keyStreamPin = new PinnedMemory<byte>(_keyStream);
            _engineStatePin = new PinnedMemory<uint>(_engineState);
            _bufferPin = new PinnedMemory<byte>(_buffer);
            _xPin = new PinnedMemory<uint>(_x);

            Rounds = rounds;
            SetKey(key, iv);
        }

        public void Dispose()
        {
            Reset();
            _keyStreamPin?.Dispose();
            _engineStatePin?.Dispose();
            _bufferPin?.Dispose();
            _xPin?.Dispose();
        }

        internal void PackTauOrSigma(int keyLength, uint[] state, int stateOffset)
        {
            var tsOff = (keyLength - 16) / 4;
            state[stateOffset] = TauSigma[tsOff];
            state[stateOffset + 1] = TauSigma[tsOff + 1];
            state[stateOffset + 2] = TauSigma[tsOff + 2];
            state[stateOffset + 3] = TauSigma[tsOff + 3];
        }

        public int GetLength()
        {
            return _buffer.Length;
        }

        public void Update(byte value)
        {
            var block = new byte[1];
            block[0] = value;
            _buffer = _buffer == null ? block : Append(_buffer, block);
        }

        public void UpdateBlock(byte[] value, int offset, int length)
        {
            DataLength(value, offset, length, "input buffer too short");

            var block = new byte[length];
            Array.Copy(value, offset, block, 0, length);
            _buffer = _buffer == null ? block : Append(_buffer, block);
        }

        public void UpdateBlock(PinnedMemory<byte> value, int offset, int length)
        {
            DataLength(value, offset, length, "input buffer too short");

            var block = new byte[length];
            Array.Copy(value.ToArray(), offset, block, 0, length);
            _buffer = _buffer == null ? block : Append(_buffer, block);
        }

        public void DoFinal(PinnedMemory<byte> output, int offset)
        {
            OutputLength(output, offset, _buffer.Length, "output buffer too short");

            if (LimitExceeded((uint) _buffer.Length))
                throw new Exception("2^70 byte limit per IV would be exceeded; Change IV");

            for (var i = 0; i < _buffer.Length; i++)
            {
                if (_index == 0)
                {
                    GenerateKeyStream(_keyStream);
                    AdvanceCounter();
                }

                output[i + offset] = (byte) (_keyStream[_index] ^ _buffer[i]);
                _index = (_index + 1) & 63;
            }
        }

        public void DoFinal(byte[] output, int offset)
        {
            OutputLength(output, offset, _buffer.Length, "output buffer too short");

            if (LimitExceeded((uint) _buffer.Length))
                throw new Exception("2^70 byte limit per IV would be exceeded; Change IV");

            for (var i = 0; i < _buffer.Length; i++)
            {
                if (_index == 0)
                {
                    GenerateKeyStream(_keyStream);
                    AdvanceCounter();
                }

                output[i + offset] = (byte) (_keyStream[_index] ^ _buffer[i]);
                _index = (_index + 1) & 63;
            }
        }

        public void Reset()
        {
            _index = 0;
            ResetLimitCounter();
            ResetCounter();
        }

        /**
         * Rotate left
         *
         * @param   x   value to rotate
         * @param   y   amount to rotate x
         *
         * @return  rotated x
         */
        private uint R(uint x, int y)
        {
            return (x << y) | (x >> (32 - y));
        }

        private void ResetLimitCounter()
        {
            _cW0 = 0;
            _cW1 = 0;
            _cW2 = 0;
        }

        private bool LimitExceeded()
        {
            if (++_cW0 == 0)
                if (++_cW1 == 0)
                    return (++_cW2 & 0x20) != 0; // 2^(32 + 32 + 6)

            return false;
        }

        /*
         * this relies on the fact len will always be positive.
         */
        private bool LimitExceeded(uint len)
        {
            var old = _cW0;
            _cW0 += len;
            if (_cW0 < old)
                if (++_cW1 == 0)
                    return (++_cW2 & 0x20) != 0; // 2^(32 + 32 + 6)

            return false;
        }

        private void DataLength(byte[] buf, int off, int len, string msg)
        {
            if (off + len > buf.Length)
                throw new Exception(msg);
        }

        private void DataLength(PinnedMemory<byte> buf, int off, int len, string msg)
        {
            if (off + len > buf.Length)
                throw new Exception(msg);
        }

        private void OutputLength(PinnedMemory<byte> buf, int off, int len, string msg)
        {
            if (off + len > buf.Length)
                throw new Exception(msg);
        }

        private void OutputLength(byte[] buf, int off, int len, string msg)
        {
            if (off + len > buf.Length)
                throw new Exception(msg);
        }

        internal static void UInt32_To_LE(uint n, byte[] bs)
        {
            bs[0] = (byte) n;
            bs[1] = (byte) (n >> 8);
            bs[2] = (byte) (n >> 16);
            bs[3] = (byte) (n >> 24);
        }

        internal static void UInt32_To_LE(uint n, byte[] bs, int off)
        {
            bs[off] = (byte) n;
            bs[off + 1] = (byte) (n >> 8);
            bs[off + 2] = (byte) (n >> 16);
            bs[off + 3] = (byte) (n >> 24);
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
                   | ((uint) bs[off + 1] << 8)
                   | ((uint) bs[off + 2] << 16)
                   | ((uint) bs[off + 3] << 24);
        }

        internal static uint LE_To_UInt32(byte[] bs, int off)
        {
            return bs[off]
                   | ((uint) bs[off + 1] << 8)
                   | ((uint) bs[off + 2] << 16)
                   | ((uint) bs[off + 3] << 24);
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
            if (++_engineState[12] == 0) ++_engineState[13];
        }

        private void ResetCounter()
        {
            _engineState[12] = _engineState[13] = 0;
        }

        private void SetKey(PinnedMemory<byte> keyBytes, byte[] ivBytes)
        {
            if (keyBytes != null)
            {
                if (keyBytes.Length != 16 && keyBytes.Length != 32)
                    throw new ArgumentException("ChaCha20 requires 128 bit or 256 bit key");

                PackTauOrSigma(keyBytes.Length, _engineState, 0);

                // Key
                LE_To_UInt32(keyBytes, 0, _engineState, 4, 4);
                LE_To_UInt32(keyBytes, keyBytes.Length - 16, _engineState, 8, 4);
            }

            // IV
            LE_To_UInt32(ivBytes, 0, _engineState, 14, 2);
        }

        private void GenerateKeyStream(byte[] output)
        {
            ChachaCore(Rounds, _engineState, _x);
            UInt32_To_LE(_x, output, 0);
        }

        /// <summary>
        ///     ChaCha function.
        /// </summary>
        /// <param name="rounds">The number of ChaCha rounds to execute</param>
        /// <param name="input">The input words.</param>
        /// <param name="x">The ChaCha state to modify.</param>
        private void ChachaCore(int rounds, uint[] input, uint[] x)
        {
            if (input.Length != 16)
                throw new ArgumentException();
            if (x.Length != 16)
                throw new ArgumentException();
            if (rounds % 2 != 0)
                throw new ArgumentException("Number of rounds must be even");

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
                x00 += x04;
                x12 = R(x12 ^ x00, 16);
                x08 += x12;
                x04 = R(x04 ^ x08, 12);
                x00 += x04;
                x12 = R(x12 ^ x00, 8);
                x08 += x12;
                x04 = R(x04 ^ x08, 7);
                x01 += x05;
                x13 = R(x13 ^ x01, 16);
                x09 += x13;
                x05 = R(x05 ^ x09, 12);
                x01 += x05;
                x13 = R(x13 ^ x01, 8);
                x09 += x13;
                x05 = R(x05 ^ x09, 7);
                x02 += x06;
                x14 = R(x14 ^ x02, 16);
                x10 += x14;
                x06 = R(x06 ^ x10, 12);
                x02 += x06;
                x14 = R(x14 ^ x02, 8);
                x10 += x14;
                x06 = R(x06 ^ x10, 7);
                x03 += x07;
                x15 = R(x15 ^ x03, 16);
                x11 += x15;
                x07 = R(x07 ^ x11, 12);
                x03 += x07;
                x15 = R(x15 ^ x03, 8);
                x11 += x15;
                x07 = R(x07 ^ x11, 7);
                x00 += x05;
                x15 = R(x15 ^ x00, 16);
                x10 += x15;
                x05 = R(x05 ^ x10, 12);
                x00 += x05;
                x15 = R(x15 ^ x00, 8);
                x10 += x15;
                x05 = R(x05 ^ x10, 7);
                x01 += x06;
                x12 = R(x12 ^ x01, 16);
                x11 += x12;
                x06 = R(x06 ^ x11, 12);
                x01 += x06;
                x12 = R(x12 ^ x01, 8);
                x11 += x12;
                x06 = R(x06 ^ x11, 7);
                x02 += x07;
                x13 = R(x13 ^ x02, 16);
                x08 += x13;
                x07 = R(x07 ^ x08, 12);
                x02 += x07;
                x13 = R(x13 ^ x02, 8);
                x08 += x13;
                x07 = R(x07 ^ x08, 7);
                x03 += x04;
                x14 = R(x14 ^ x03, 16);
                x09 += x14;
                x04 = R(x04 ^ x09, 12);
                x03 += x04;
                x14 = R(x14 ^ x03, 8);
                x09 += x14;
                x04 = R(x04 ^ x09, 7);
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

        public T[] Append<T>(T[] source, T[] destination, int sourceLength = 0, int destinationLength = 0)
        {
            var expandSourceLength = sourceLength > 0 ? sourceLength : source.Length;
            var expandDestinationLength = destinationLength > 0 ? destinationLength : destination.Length;
            var expanded = new T[expandSourceLength + expandDestinationLength];

            Array.Copy(source, 0, expanded, 0, expandSourceLength);
            Array.Copy(destination, 0, expanded, expandSourceLength, expandDestinationLength);

            return expanded;
        }
    }
}