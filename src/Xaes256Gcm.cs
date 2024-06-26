using System.Diagnostics;
using System.Security.Cryptography;

namespace Xaes256Gcm;

/// <summary>
/// Implements the XAES-256-GCM algorithm.
/// </summary>
/// <remarks>
/// The algorithm is specified in https://github.com/C2SP/C2SP/blob/main/XAES-256-GCM.md.
/// </remarks>
public sealed class Xaes256Gcm : IDisposable {
    private const int AES_BLOCK_SIZE = 16;
    private const int AES_DERIVE_KEY_SIZE = 32;
    private const int AES_GCM_TAG_SIZE = 16;

    private byte[]? _k1 = new byte[AES_BLOCK_SIZE];
    private readonly Aes _aes;

    /// <summary>
    /// Gets the nonce size, in bytes.
    /// </summary>
    public static int NonceSize => 24;

    /// <summary>
    /// Gets the key size, in bytes.
    /// </summary>
    public static int KeySize => 32;

    /// <summary>
    /// Gets the key size, in bytes.
    /// </summary>
    public static int Overhead => AES_GCM_TAG_SIZE;

    /// <summary>
    /// Creates a new instance of <see cref="Xaes256Gcm"/>.
    /// </summary>
    /// <param name="key">The key.</param>
    /// <exception cref="ArgumentException">
    /// <paramref name="key"/> length is not exactly <see cref="KeySize"/>.
    /// </exception>
    public Xaes256Gcm(ReadOnlySpan<byte> key) :this(key.ToArray()) {
    }

    /// <summary>
    /// Creates a new instance of <see cref="Xaes256Gcm"/>.
    /// </summary>
    /// <param name="key">The key.</param>
    /// <exception cref="ArgumentException">
    /// <paramref name="key"/> length is not exactly <see cref="KeySize"/>.
    /// </exception>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="key"/> length is <see langword="null" />.
    /// </exception>
    public Xaes256Gcm(byte[] key) {
        ArgumentNullException.ThrowIfNull(key);

        if (key.Length != KeySize) {
            throw new ArgumentException("Key must be exactly 32 bytes (256-bits).", nameof(key));
        }

        _aes = Aes.Create();
        _aes.Key = key;
        _k1 = new byte[AES_BLOCK_SIZE];
        _aes.EncryptEcb(_k1, _k1, PaddingMode.None);

        byte msb = 0;

        unchecked {
            for (int i = _k1.Length - 1; i >= 0; i--) {
                byte msbC = msb;
                msb = (byte)(_k1[i] >> 7);
                _k1[i] = (byte)((_k1[i] << 1) | msbC);
            }

            _k1[^1] ^= (byte)(msb * 0b10000111);
        }
    }

    /// <summary>
    /// Seals, or encrypts, the plaintext with optional additional data.
    /// </summary>
    /// <param name="plaintext">The plaintext to encrypt.</param>
    /// <param name="nonce">The nonce.</param>
    /// <param name="additionalData">Optional additional data to authenticate.</param>
    /// <param name="destination">The destination to receive the ciphertext.</param>
    /// <exception cref="ArgumentException">
    /// <paramref name="nonce"/> is not exactly <see cref="NonceSize"/> bytes in length.
    /// - or -
    /// <paramref name="destination"/> is not exactly the size of the plaintext, plus <see cref="Overhead"/>.
    /// </exception>
    /// <remarks>
    /// This implementation appends the authentication tag at the end of the <paramref name="destination" />.
    /// </remarks>
    public void Seal(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, Span<byte> destination, ReadOnlySpan<byte> additionalData = default) {
        ObjectDisposedException.ThrowIf(_k1 is null, typeof(Xaes256Gcm));

        if (nonce.Length != NonceSize) {
            throw new ArgumentException("Nonce must be 24 bytes in length.", nameof(nonce));
        }

        if (destination.Length != plaintext.Length + Overhead) {
            throw new ArgumentException("Destination must be exactly the size of the plaintext plus 16 for overhead.");
        }

        Span<byte> key = stackalloc byte[AES_DERIVE_KEY_SIZE];
        DeriveKey(nonce[..12], key);
        ReadOnlySpan<byte> n = nonce[12..];

        using AesGcm gcm = new(key, tagSizeInBytes: AES_GCM_TAG_SIZE);
        gcm.Encrypt(n, plaintext, destination[..^AES_GCM_TAG_SIZE], destination[^AES_GCM_TAG_SIZE..], additionalData);
    }

    /// <summary>
    /// Seals, or encrypts, the plaintext with optional additional data.
    /// </summary>
    /// <param name="plaintext">The plaintext to encrypt.</param>
    /// <param name="nonce">The nonce.</param>
    /// <param name="additionalData">Optional additional data to authenticate.</param>
    /// <param name="destination">The destination to receive the ciphertext.</param>
    /// <exception cref="ArgumentException">
    /// <paramref name="nonce"/> is not exactly <see cref="NonceSize"/> in in length.
    /// </exception>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="nonce"/> or <paramref name="plaintext"/> is <see langword="null" />.
    /// </exception>
    /// <remarks>
    /// This implementation appends the authentication tag at the end of the returned value. />.
    /// </remarks>
    /// <returns>
    /// The encrypted data, with the authentication tag appended.
    /// </returns>
    public byte[] Seal(byte[] plaintext, byte[] nonce, byte[]? additionalData = null) {
        ObjectDisposedException.ThrowIf(_k1 is null, typeof(Xaes256Gcm));

        ArgumentNullException.ThrowIfNull(plaintext);
        ArgumentNullException.ThrowIfNull(nonce);

        byte[] buffer = new byte[plaintext.Length + Overhead];
        Seal(plaintext, nonce, buffer, additionalData);
        return buffer;
    }

    /// <summary>
    ///  Opens, or decrypts, encrypted data.
    /// </summary>
    /// <param name="ciphertext">The data to decrypt.</param>
    /// <param name="nonce">The nonce.</param>
    /// <param name="destination">The destination to receive the plaintext data.</param>
    /// <param name="additionalData">Optional data to authentication.</param>
    /// <exception cref="ArgumentException">
    /// <paramref name="nonce"/> is not exactly <see cref="NonceSize"/> bytes in length.
    /// - or -
    /// <paramref name="destination"/> is not exactly the size of the ciphertext, minus <see cref="Overhead"/>.
    /// </exception>
    /// <exception cref="AuthenticationTagMismatchException">The ciphertext or additional data did not authenticate.</exception>
    /// <exception cref="ObjectDisposedException">The current instance has been disposed.</exception>
    public void Open(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce, Span<byte> destination, ReadOnlySpan<byte> additionalData = default) {
        ObjectDisposedException.ThrowIf(_k1 is null, typeof(Xaes256Gcm));

        if (nonce.Length != NonceSize) {
            throw new ArgumentException("Nonce must be 24 bytes in length.", nameof(nonce));
        }

        if (ciphertext.Length < AES_GCM_TAG_SIZE) {
            throw new AuthenticationTagMismatchException();
        }

        if (ciphertext.Length - AES_GCM_TAG_SIZE != destination.Length) {
            throw new ArgumentException("Destination is the incorrect length.", nameof(destination));
        }

        Span<byte> key = stackalloc byte[AES_DERIVE_KEY_SIZE];
        DeriveKey(nonce[..12], key);
        ReadOnlySpan<byte> n = nonce[12..];

        using AesGcm gcm = new(key, tagSizeInBytes: AES_GCM_TAG_SIZE);
        gcm.Decrypt(n, ciphertext[..^AES_GCM_TAG_SIZE], ciphertext[^AES_GCM_TAG_SIZE..], destination, additionalData);
    }

    /// <summary>
    ///  Opens, or decrypts, encrypted data.
    /// </summary>
    /// <param name="ciphertext">The data to decrypt.</param>
    /// <param name="nonce">The nonce.</param>
    /// <param name="additionalData">Optional data to authentication.</param>
    /// <returns>The decrypted data.</returns>
    /// <exception cref="ArgumentException">
    /// <paramref name="nonce"/> is not exactly <see cref="NonceSize"/> bytes in length.
    /// - or -
    /// <paramref name="destination"/> is not exactly the size of the ciphertext, minus <see cref="Overhead"/>.
    /// </exception>
    /// <exception cref="AuthenticationTagMismatchException">The ciphertext or additional data did not authenticate.</exception>
    /// <exception cref="ObjectDisposedException">The current instance has been disposed.</exception>
    public byte[] Open(byte[] ciphertext, byte[] nonce, byte[]? additionalData = null) {
        ArgumentNullException.ThrowIfNull(ciphertext);
        ArgumentNullException.ThrowIfNull(nonce);

        if (ciphertext.Length < AES_GCM_TAG_SIZE) {
            throw new AuthenticationTagMismatchException();
        }

        byte[] buffer = new byte[ciphertext.Length - AES_GCM_TAG_SIZE];
        Open(ciphertext, nonce, buffer, additionalData);
        return buffer;
    }

    private void DeriveKey(ReadOnlySpan<byte> nonce, Span<byte> destination) {
        Debug.Assert(destination.Length == AES_BLOCK_SIZE * 2);
        Span<byte> m1 = [0, 1, (byte)'X', 0, ..nonce];
        Span<byte> m2 = [0, 2, (byte)'X', 0, ..nonce];
        XorInPlace(m1, _k1);
        XorInPlace(m2, _k1);
        _aes.EncryptEcb(m1, m1, PaddingMode.None);
        _aes.EncryptEcb(m2, m2, PaddingMode.None);

        m1.CopyTo(destination);
        m2.CopyTo(destination[m1.Length..]);
    }

    private static void XorInPlace(Span<byte> destination, ReadOnlySpan<byte> other) {
        Debug.Assert(destination.Length == other.Length);

        for (int i = 0; i < destination.Length; i++) {
            destination[i] ^= other[i];
        }
    }

    public void Dispose() {
        _aes.Dispose();
        CryptographicOperations.ZeroMemory(_k1);
        _k1 = null;
    }
}
