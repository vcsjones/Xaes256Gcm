using Xaes256Gcm.Benches;
using BenchmarkDotNet.Running;
using BenchmarkDotNet.Attributes;
using System.Security.Cryptography;

BenchmarkRunner.Run<Xaes256GcmBenches>(args: args);

namespace Xaes256Gcm.Benches {
    public class Xaes256GcmBenches {
        private Xaes256Gcm _xaes;
        private byte[] _plaintext;
        private byte[] _nonce;
        private byte[] _destination;
        private byte[] _ciphertext;

        [Params(0, 32, 64)]
        public int PlaintextSize { get; set; }

        [GlobalSetup]
        public void GlobalSetup() {
            _plaintext = RandomNumberGenerator.GetBytes(PlaintextSize);
            _nonce = RandomNumberGenerator.GetBytes(Xaes256Gcm.NonceSize);
            _destination = new byte[_plaintext.Length + Xaes256Gcm.Overhead];
            byte[] key = RandomNumberGenerator.GetBytes(Xaes256Gcm.KeySize);
            _xaes = new(key);
            _ciphertext = _xaes.Seal(_plaintext, _nonce);
        }

        [Benchmark]
        public byte[] XAES_Seal_Array() {
            return _xaes.Seal(_plaintext, _nonce);
        }

        [Benchmark]
        public byte[] XAES_Seal_Span() {
            _xaes.Seal(_plaintext.AsSpan(), _nonce.AsSpan(), _destination.AsSpan());
            return _destination;
        }

        [Benchmark]
        public byte[] XAES_Open_Span() {
            _xaes.Open(_ciphertext.AsSpan(), _nonce.AsSpan(), _destination.AsSpan(..^Xaes256Gcm.Overhead));
            return _destination;
        }

        [Benchmark]
        public byte[] XAES_Open_Array() {
            return _xaes.Open(_ciphertext, _nonce);
        }
    }
}
