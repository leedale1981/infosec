using System.Net;
using System.Net.Sockets;

namespace LD.InfoSec.Network.Linux;

public static class NetworkService
{
    public static async Task SendSynPackets(string targetIp, ushort targetPort, string sourceIp, ushort sourcePort, int packetCount)
    {
        using Socket socket = new(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Raw);
        IPAddress sourceIpAddress = IPAddress.Parse(sourceIp);
        IPAddress targetIpAddress = IPAddress.Parse(targetIp);
        IPEndPoint ipEndPoint = new(targetIpAddress, targetPort);
        
        byte[] packetBytes = Shared.PacketGenerator.GetRawIpWrapper(sourceIpAddress, targetIpAddress, targetPort, sourcePort);
        
        for (int index = 0; index < packetCount; index++)
        {
            await socket.SendToAsync(new ArraySegment<byte>(packetBytes), ipEndPoint);
        }
    }
}
