using System.Security.Cryptography;

namespace Server
{
    internal class ECDHEServer
    {
        private ECDiffieHellman _serverEcdh;
        public byte[] PublicKey { get; private set; }

        public ECDHEServer()
        {
            // Генеруємо пару ключів ECDHE
            _serverEcdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            PublicKey = _serverEcdh.PublicKey.ToByteArray();
        }

        // Обчислюємо спільний секрет на основі відкритого ключа клієнта
        public byte[] ComputeSharedSecret(byte[] clientPublicKey)
        {
            using ECDiffieHellman clientEcdh = ECDiffieHellman.Create();
            clientEcdh.ImportSubjectPublicKeyInfo(clientPublicKey, out _);
            return _serverEcdh.DeriveKeyMaterial(clientEcdh.PublicKey);
        }
    }
}
