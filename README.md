XAES-256-GCM for .NET
========

This is an implementation of XAES-256-GCM as proposed by Filippo Valsorda, for .NET 8+.

Resources:
* Original post by Filippo: https://words.filippo.io/dispatches/xaes-256-gcm/
* The XAES-256-GCM specification: https://github.com/C2SP/C2SP/blob/main/XAES-256-GCM.md
* Reference implementations for Go and OpenSSL: https://github.com/C2SP/C2SP/tree/main/XAES-256-GCM


# Using

```C#
byte[] key; // Assign to some key
byte[] nonce = RandomNumberGenerator.GetBytes(Xaes256Gcm.NonceSize);
byte[] plaintext = "Hello XAES-256-GCM from .NET"u8.ToArray();

using Xaes256Gcm xaes = new(key);

// Seal, or encrypt
byte[] ciphertext = xaes.Seal(plaintext, nonce); // AAD can optionally be passed as a 3rd argument

// Open, or decrypt
byte[] decrypted = xaes.Open(ciphertext, nonce);
```

Additional overloads that accept Span-based inputs and outputs are also available.

# Tests

Tests use inputs and outputs from the reference implementation and can be run with `dotnet test`.
The accumulation tests require SHAKE-128 squeezing, which currently requires a preview of .NET 9.
If you have .NET 9 Preview 7 or later, the accumulation tests can be run with with
`dotnet test /p:RunAccumulationTests=true`.

If the switch is used without the requisite version of .NET, the tests will fail to compile.
When .NET 9 stabilizes the switch will not be required.
