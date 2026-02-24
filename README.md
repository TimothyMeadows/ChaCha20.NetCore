# ChaCha20.NetCore

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![nuget](https://img.shields.io/nuget/v/ChaCha20.NetCore.svg)](https://www.nuget.org/packages/ChaCha20.NetCore/)

`ChaCha20.NetCore` is a .NET implementation of the [ChaCha20](https://datatracker.ietf.org/doc/html/rfc8439) stream cipher.

The implementation is optimized for secure memory handling and integrates with [`PinnedMemory`](https://github.com/TimothyMeadows/PinnedMemory) to support memory-sensitive workflows.

> This package provides ChaCha20 encryption/decryption only. It does **not** include authentication (for example, Poly1305).

---

## Table of contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Quick start](#quick-start)
- [API reference](#api-reference)
  - [`ChaCha20`](#chacha20)
- [Usage notes](#usage-notes)
- [Security notes](#security-notes)
- [Validation and test vectors](#validation-and-test-vectors)
- [Development](#development)
- [License](#license)

---

## Requirements

- **.NET 8 SDK** for building/testing this repository.
- Target runtime/framework for the project: **.NET 8**.

The repository includes a `global.json` to pin the SDK family used for development.

---

## Installation

### NuGet Package Manager (CLI)

```bash
dotnet add package ChaCha20.NetCore
```

### Package Manager Console

```powershell
Install-Package ChaCha20.NetCore
```

### NuGet Gallery

- https://www.nuget.org/packages/ChaCha20.NetCore/

---

## Quick start

```csharp
using System;
using System.Security.Cryptography;
using ChaCha20.NetCore;
using PinnedMemory;

var nonce = RandomNumberGenerator.GetBytes(12);   // RFC 8439 nonce size
var keyBytes = RandomNumberGenerator.GetBytes(32); // 256-bit key
var plaintext = new byte[] { 63, 61, 77, 20, 63, 61, 77, 20, 63, 61, 77 };

using var key = new PinnedMemory<byte>(keyBytes, false);
using var chacha20 = new ChaCha20(key, nonce); // default: 20 rounds

chacha20.UpdateBlock(plaintext, 0, plaintext.Length);

using var output = new PinnedMemory<byte>(new byte[chacha20.GetLength()]);
chacha20.DoFinal(output, 0);

var ciphertext = output.ToArray();

// ChaCha20 decrypts by applying the same keystream operation again
chacha20.Reset();
chacha20.UpdateBlock(ciphertext, 0, ciphertext.Length);

using var decrypted = new PinnedMemory<byte>(new byte[chacha20.GetLength()]);
chacha20.DoFinal(decrypted, 0);
```

---

## API reference

## `ChaCha20`

### Constructor

```csharp
ChaCha20(PinnedMemory<byte> key, byte[] nonce, int rounds = 20)
```

- `key` must be 32 bytes (256-bit).
- `nonce` must be 12 bytes (96-bit RFC 8439 nonce).
- `rounds` must be positive and even (20 is standard ChaCha20).

### Core members

```csharp
int Rounds { get; }
int GetLength()
byte[] GetBuffer()
void Update(byte value)
void UpdateBlock(byte[] value, int offset, int length)
void UpdateBlock(PinnedMemory<byte> value, int offset, int length)
void DoFinal(byte[] output, int offset)
void DoFinal(PinnedMemory<byte> output, int offset)
void Reset()
void Dispose()
```

### Behavior notes

- `GetLength()` returns the current buffered input length in bytes.
- `DoFinal(...)` writes encrypted/decrypted output for the currently buffered input.
- `Reset()` clears buffered input and rewinds counter/index state to the initial position for the same key/nonce.
- `Dispose()` clears internal state and pinned buffers.

---

## Usage notes

### 1) Never reuse a nonce with the same key

ChaCha20 is a stream cipher. Reusing `(key, nonce)` across different plaintexts can reveal relationships between messages.

### 2) Add authentication separately

ChaCha20 alone does not provide tamper detection. For authenticated encryption, pair with Poly1305 (ChaCha20-Poly1305) or use an AEAD library.

### 3) Treat keys as sensitive material

- Keep keys in pinned memory where practical.
- Dispose cipher instances promptly (`using` blocks).
- Avoid logging keys, nonces, or raw plaintext in production diagnostics.

### 4) Use explicit framing for protocols

If you split messages across frames/chunks, ensure both sender and receiver agree on:

- nonce lifecycle
- message boundaries
- replay protections
- encoding/canonicalization of higher-level payloads

---

## Security notes

- ChaCha20 in this package follows RFC 8439 parameter conventions:
  - 256-bit key (32 bytes)
  - 96-bit nonce (12 bytes)
  - 32-bit block counter
- This implementation enforces the ChaCha20 per-nonce processing limit and will throw if exceeded.
- Cryptographic integration should be reviewed against your protocol and threat model.

---

## Validation and test vectors

The test project includes RFC 8439-focused verification, including keystream generation and roundtrip encryption/decryption behavior.

Run tests with:

```bash
dotnet test ChaCha20.NetCore.sln
```

---

## Development

### Build

```bash
dotnet build ChaCha20.NetCore.sln
```

### Test

```bash
dotnet test ChaCha20.NetCore.sln
```

If `dotnet` is installed locally but not on `PATH`, invoke it explicitly:

```bash
$HOME/.dotnet/dotnet test ChaCha20.NetCore.sln
```

---

## License

MIT. See [LICENSE](LICENSE).
