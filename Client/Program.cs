using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

class SecureClient
{
    private const string ServerAddress = "127.0.0.1"; // Локальний сервер
    private const int ServerPort = 8080; // Порт, який використовує сервер

    public static void Main()
    {
        Console.WriteLine("Client starting...");

        // Підключення до сервера
        using TcpClient client = new TcpClient(ServerAddress, ServerPort);
        using NetworkStream networkStream = client.GetStream();
        using SslStream sslStream = new SslStream(networkStream, false, ValidateServerCertificate);

        // Аутентифікація через TLS
        X509Certificate2 clientCertificate = LoadClientCertificate();
        sslStream.AuthenticateAsClient(ServerAddress, new X509CertificateCollection { clientCertificate }, false);

        Console.WriteLine("TLS connection established.");

        // Ініціалізація ECDHE
        ECDiffieHellman clientECDH = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        byte[] clientPublicKey = clientECDH.PublicKey.ToByteArray();

        // Отримання публічного ключа сервера
        byte[] serverPublicKey = new byte[64];
        sslStream.Read(serverPublicKey, 0, serverPublicKey.Length);

        // Імпортуємо відкритий ключ сервера у форматі ECDiffieHellmanPublicKey
        using ECDiffieHellman serverECDH = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        serverECDH.ImportSubjectPublicKeyInfo(serverPublicKey, out _); // Імпортуємо відкритий ключ сервера

        // Обчислення спільного секрету
        byte[] sharedSecret = clientECDH.DeriveKeyMaterial(serverECDH.PublicKey);
        Console.WriteLine("Shared secret established.");

        // Захищене шифрування повідомлення
        string message = "Hello, server! This is a secure message from the client.";
        byte[] encryptedMessage = EncryptData(Encoding.UTF8.GetBytes(message), sharedSecret);
        sslStream.Write(encryptedMessage);
        sslStream.Flush();
        Console.WriteLine("Encrypted message sent to the server.");

        // Отримання відповіді від сервера
        byte[] response = new byte[1024];
        int bytesRead = sslStream.Read(response, 0, response.Length);
        byte[] decryptedResponse = DecryptData(response[..bytesRead], sharedSecret);

        Console.WriteLine("Server response: " + Encoding.UTF8.GetString(decryptedResponse));
    }

    // Завантаження сертифікату клієнта
    private static X509Certificate2 LoadClientCertificate()
    {
        string certPath = "../../../client_key.pfx";
        string certPassword = "qwerty_1234";
        return new X509Certificate2(certPath, certPassword);
    }

    // Перевірка сертифікату сервера
    private static bool ValidateServerCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
    {
        if (sslPolicyErrors == SslPolicyErrors.None)
            return true;

        Console.WriteLine("Server certificate validation failed.");
        return false;
    }

    // Шифрування даних AES-GCM
    private static byte[] EncryptData(byte[] data, byte[] key)
    {
        using AesGcm aes = new AesGcm(key);
        byte[] nonce = new byte[AesGcm.NonceByteSizes.MaxSize];
        RandomNumberGenerator.Fill(nonce);

        byte[] ciphertext = new byte[data.Length];
        byte[] tag = new byte[AesGcm.TagByteSizes.MaxSize];

        aes.Encrypt(nonce, data, ciphertext, tag);
        return nonce.Concat(ciphertext).Concat(tag).ToArray();
    }

    // Розшифрування даних AES-GCM
    private static byte[] DecryptData(byte[] encryptedData, byte[] key)
    {
        using AesGcm aes = new AesGcm(key);

        byte[] nonce = encryptedData[..AesGcm.NonceByteSizes.MaxSize];
        byte[] ciphertext = encryptedData[AesGcm.NonceByteSizes.MaxSize..^AesGcm.TagByteSizes.MaxSize];
        byte[] tag = encryptedData[^AesGcm.TagByteSizes.MaxSize..];

        byte[] plaintext = new byte[ciphertext.Length];
        aes.Decrypt(nonce, ciphertext, tag, plaintext);
        return plaintext;
    }
}
