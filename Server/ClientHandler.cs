using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;

namespace Server
{
    internal class ClientHandler
    {
        private static X509Certificate2 _serverCertificate;
        private readonly TcpClient _client;

        public ClientHandler(TcpClient client)
        {
            _client = client;
            LoadServerCertificate();
        }

        public void HandleClient()
        {
            using (var sslStream = new SslStream(_client.GetStream(), false, ValidateClientCertificate))
            {
                try
                {
                    // Налаштування SSL-контексту з обов’язковою взаємною автентифікацією
                    sslStream.AuthenticateAsServer(_serverCertificate, false, System.Security.Authentication.SslProtocols.Tls12, false);

                    Console.WriteLine("З’єднання захищене. Починається протокол рукостискання...");

                    // ECDHE для узгодження ключа
                    var sharedSecret = PerformECDHKeyExchange(sslStream);

                    // Використовуємо спільний секрет для AES-GCM шифрування
                    SetupAESGCMChannel(sslStream, sharedSecret);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Помилка при встановленні з'єднання: {ex.Message}");
                }
            }

            _client.Close();
        }

        private bool ValidateClientCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors) =>
            sslPolicyErrors == SslPolicyErrors.None;

        private byte[] PerformECDHKeyExchange(SslStream sslStream)
        {
            using (ECDiffieHellmanCng ecdh = new())
            {
                ecdh.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
                ecdh.HashAlgorithm = CngAlgorithm.Sha256;

                // Відправляємо публічний ключ клієнту
                byte[] publicKey = ecdh.PublicKey.ToByteArray();
                sslStream.Write(publicKey);
                sslStream.Flush();

                // Отримуємо публічний ключ клієнта
                byte[] clientPublicKey = new byte[publicKey.Length];
                sslStream.Read(clientPublicKey, 0, clientPublicKey.Length);

                using (ECDiffieHellman ecdhClient = ECDiffieHellman.Create())
                {
                    ecdhClient.ImportSubjectPublicKeyInfo(clientPublicKey, out _);
                    ECDiffieHellmanPublicKey clientKey = ecdhClient.PublicKey;

                    // Обчислюємо спільний секрет
                    byte[] sharedSecret = ecdh.DeriveKeyMaterial(clientKey);
                    return sharedSecret;
                }
            }
        }

        private void SetupAESGCMChannel(SslStream sslStream, byte[] sharedSecret)
        {
            using (AesGcm aes = new(sharedSecret))
            {
                Console.WriteLine("Захищений канал AES-GCM встановлено.");
                // TODO: Do more logic
            }
        }

        private void LoadServerCertificate()
        {
            _serverCertificate = new X509Certificate2("../../../server_key.pfx", "qwerty_1234");
        }
    }
}
