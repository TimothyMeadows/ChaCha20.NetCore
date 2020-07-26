# ChaCha20.NetCore
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) [![nuget](https://img.shields.io/nuget/v/ChaCha20.NetCore.svg)](https://www.nuget.org/packages/ChaCha20.NetCore/)

Implementation of chacha20 cipher, designed by D. J. Bernstein. Optimized for [PinnedMemory](https://github.com/TimothyMeadows/PinnedMemory).

# Install

From a command prompt
```bash
dotnet add package ChaCha20.NetCore
```

```bash
Install-Package ChaCha20.NetCore
```

You can also search for package via your nuget ui / website:

https://www.nuget.org/packages/ChaCha20.NetCore/

# Examples

You can find more examples in the github examples project.

```csharp
var iv = new byte[16];
var key = new byte[32];

using var provider = new RNGCryptoServiceProvider();
provider.GetBytes(iv);
provider.GetBytes(key);

using var keyPin = new PinnedMemory<byte>(key, false);
using var cipher = new ChaCha20(keyPin, iv);
cipher.UpdateBlock(new PinnedMemory<byte>(new byte[] {63, 61, 77, 20, 63, 61, 77, 20, 63, 61, 77}, false), 0, 11); // caw caw caw in utf8

using var output = new PinnedMemory<byte>(new byte[cipher.GetLength()]);
cipher.DoFinal(output, 0);
```

# Constructor

```csharp
ChaCha20(PinnedMemory<byte> key, byte[] iv, int rounds = 20)
```

# Methods

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

Produce the final cipher outputting to pinned memory. Key & iv remain until dispose is called.
```csharp
void DoFinal(PinnedMemory<byte> output, int outOff)
```

Reset the cipher back to it's initial state for further processing. Key & iv remain until dispose is called.
```csharp
void Reset()
```

Clear key & iv, reset cipher back to it's initial state.
```csharp
void Dispose()
```
