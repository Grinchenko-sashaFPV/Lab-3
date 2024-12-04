using Server;
using System.Net.Sockets;
using System.Net;

// Старт прослуховування з’єднань
StartServer();

void StartServer()
{
    TcpListener listener = new TcpListener(IPAddress.Any, 8080);
    listener.Start();
    Console.WriteLine("Сервер запущений і очікує підключення...");

    while (true)
    {
        var client = listener.AcceptTcpClient();
        Console.WriteLine("Клієнт підключився.");

        // Запуск обробника клієнта у новому потоці
        var clientHandler = new ClientHandler(client);
        clientHandler.HandleClient();
    }
}
