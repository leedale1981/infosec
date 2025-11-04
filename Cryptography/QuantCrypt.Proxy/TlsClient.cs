using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;

namespace QuantCrypt.Proxy;

public class TlsClient(ILogger logger, IPEndPoint endpoint)
{
    private readonly Socket _socket = new(AddressFamily.InterNetworkV6, SocketType.Stream, ProtocolType.Tcp);

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        ListenOnEndpoint();
        while (!cancellationToken.IsCancellationRequested)
        {
            Socket client = await _socket.AcceptAsync(cancellationToken);
        }
    }

    private void ListenOnEndpoint()
    {
        _socket.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.IPv6Only, false);
        _socket.Bind(endpoint);
        _socket.Listen(512);
        logger.LogInformation("Listening on port {@Port}", _socket.LocalEndPoint);
    }
}