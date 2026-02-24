# ChaCha20.NetCore
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) [![nuget](https://img.shields.io/nuget/v/ChaCha20.NetCore.svg)](https://www.nuget.org/packages/ChaCha20.NetCore/)

Implementation of ChaCha20 stream cipher, optimized for [PinnedMemory](https://github.com/TimothyMeadows/PinnedMemory).

## Target framework

This project now targets `.NET 8` and follows RFC 8439 parameter conventions:

- 256-bit key (32 bytes)
- 96-bit nonce (12 bytes)
- 32-bit block counter

## Security notes

- Never reuse a nonce with the same key.
- Reusing a key+nonce pair reveals information about plaintexts in stream ciphers.
- This package provides encryption/decryption only; authentication (for tamper protection) is not included.
  For authenticated encryption use ChaCha20-Poly1305.

## Install

From a command prompt

```bash
dotnet add package ChaCha20.NetCore
```

```bash
Install-Package ChaCha20.NetCore
```

You can also search for package via your NuGet UI / website:

https://www.nuget.org/packages/ChaCha20.NetCore/

## Example

```csharp
var nonce = RandomNumberGenerator.GetBytes(12);
var key = RandomNumberGenerator.GetBytes(32);

using var keyPin = new PinnedMemory<byte>(key, false);
using var cipher = new ChaCha20(keyPin, nonce);
cipher.UpdateBlock(new byte[] { 63, 61, 77, 20, 63, 61, 77, 20, 63, 61, 77 }, 0, 11);

using var output = new PinnedMemory<byte>(new byte[cipher.GetLength()]);
cipher.DoFinal(output, 0);
```

## Constructor

```csharp
ChaCha20(PinnedMemory<byte> key, byte[] nonce, int rounds = 20)
```

## Methods

Get the cipher output length.

```csharp
int GetLength()
```

Update the cipher with a single byte.

```csharp
void Update(byte input)
```

Update the cipher with a pinned memory byte array.

```csharp
void UpdateBlock(PinnedMemory<byte> input, int inOff, int len)
```

Update the cipher with a byte array.

```csharp
void UpdateBlock(byte[] input, int inOff, int len)
```

Produce the final cipher outputting to pinned memory.

```csharp
void DoFinal(PinnedMemory<byte> output, int outOff)
```

Reset the cipher back to its initial state for further processing.

```csharp
void Reset()
```

Clear internal state and pinned buffers.

```csharp
void Dispose()
```
