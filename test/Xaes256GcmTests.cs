using System.Security.Cryptography;

namespace Xaes256Gcm.Tests;

public static class Xaes256GcmTests {

    [Theory]
    [MemberData(nameof(TestVectors))]
    public static void TestVectors_Span(TestVector testVector) {
        Xaes256Gcm xaes = new(testVector.Key.AsSpan());
        Span<byte> ciphertext = stackalloc byte[testVector.Plaintext.Length + Xaes256Gcm.Overhead];
        xaes.Seal(testVector.Plaintext.AsSpan(), testVector.Nonce.AsSpan(), ciphertext, testVector.Aad.AsSpan());
        Assert.Equal(testVector.Ciphertext, ciphertext);

        Span<byte> decrypted = stackalloc byte[testVector.Plaintext.Length];
        xaes.Open(ciphertext, testVector.Nonce.AsSpan(), decrypted, testVector.Aad.AsSpan());
        Assert.Equal(testVector.Plaintext, decrypted);
    }

    [Theory]
    [MemberData(nameof(TestVectors))]
    public static void TestVectors_Array(TestVector testVector) {
        Xaes256Gcm xaes = new(testVector.Key);
        byte[] ciphertext = xaes.Seal(testVector.Plaintext, testVector.Nonce, testVector.Aad);
        Assert.Equal(testVector.Ciphertext, ciphertext);

        byte[] decrypted = xaes.Open(ciphertext, testVector.Nonce, testVector.Aad);
        Assert.Equal(testVector.Plaintext, decrypted);
    }

#if RUN_ACCUMULATION_TESTS

    [Theory]
    [InlineData(10_000, "e6b9edf2df6cec60c8cbd864e2211b597fb69a529160cd040d56c0c210081939")]
    [InlineData(1_000_000, "2163ae1445985a30b60585ee67daa55674df06901b890593e824b8a7c885ab15")]
    public static void TestAccumulated(int iterations, string expected) {
        using Shake128 s = new();
        using Shake128 d = new();

        for (int i = 0; i < iterations; i++) {
            byte[] key = s.Read(Xaes256Gcm.KeySize);
            byte[] nonce = s.Read(Xaes256Gcm.NonceSize);
            byte[] lenByte;
            lenByte = s.Read(1);
            byte[] plaintext = s.Read(lenByte[0]);
            s.Read(lenByte);
            byte[] aad = s.Read(lenByte[0]);

            using Xaes256Gcm xaes = new(key);
            byte[] ciphertext = xaes.Seal(plaintext, nonce, aad);
            byte[] decrypted = xaes.Open(ciphertext, nonce, aad);
            Assert.Equal(plaintext, decrypted);
            d.AppendData(ciphertext);
        }

        Assert.Equal(expected, Convert.ToHexStringLower(d.GetHashAndReset(32)));
    }

#endif

    public record TestVector(byte[] Key, byte[] Nonce, byte[] Plaintext, byte[] Ciphertext, byte[]? Aad = default)
    {
        public TestVector(byte[] Key, ReadOnlySpan<byte> Nonce, ReadOnlySpan<byte> Plaintext, string Ciphertext, ReadOnlySpan<byte> Aad = default) :
            this(Key, Nonce.ToArray(), Plaintext.ToArray(), Convert.FromHexString(Ciphertext), Aad.ToArray())
        {
        }
    }

    public static TheoryData<TestVector> TestVectors = new() {
        new TestVector(KeyOf(0x01), "ABCDEFGHIJKLMNOPQRSTUVWX"u8, "XAES-256-GCM"u8, "ce546ef63c9cc60765923609b33a9a1974e96e52daf2fcf7075e2271"),
        new TestVector(KeyOf(0x03), "ABCDEFGHIJKLMNOPQRSTUVWX"u8, "XAES-256-GCM"u8, "986ec1832593df5443a179437fd083bf3fdb41abd740a21f71eb769d", Aad: "c2sp.org/XAES-256-GCM"u8)
    };

    private static byte[] KeyOf(byte value) {
        byte[] key = new byte[Xaes256Gcm.KeySize];
        key.AsSpan().Fill(value);
        return key;
    }
}
