using System.Net;
using System.Net.Sockets;
using System.Text;

namespace LD.InfoSec.Network.Shared;

public sealed class NetworkService
{   
    public static async Task<string> SendIcmpPackets(string targetIp, byte echoType)
    {
        using Socket socket = new(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Icmp);
        IPAddress targetIpAddress = IPAddress.Parse(targetIp);
        IPEndPoint ipEndPoint = new(targetIpAddress, 0);
        byte[] packetBytes = Shared.PacketGenerator.GetIcmpPacketBytes(echoType, 0);
        
        await socket.ConnectAsync(ipEndPoint);
        await socket.SendAsync(new ArraySegment<byte>(packetBytes), SocketFlags.None);
        
        ArraySegment<byte> buffer = new(new byte[32]);
        SocketAddress socketAddress = new(AddressFamily.InterNetwork);
        int byteNumber = socket.ReceiveFrom(buffer, SocketFlags.None, socketAddress);

        string response = Encoding.ASCII.GetString(buffer.Array ?? Array.Empty<byte>(), 0, byteNumber);
        return response;
    }
}