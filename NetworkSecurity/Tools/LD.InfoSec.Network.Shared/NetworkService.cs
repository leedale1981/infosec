using System.Net;

namespace LD.InfoSec.Network.Shared;

public static class NetworkService
{
    public static byte[] GetTcpSynPacketBytes(ushort targetPort, ushort sourcePort)
    {
        MemoryStream stream = new();
        
        byte[] sourcePortBytes = BitConverter.GetBytes(sourcePort);
        Array.Reverse(sourcePortBytes);
        stream.Write(sourcePortBytes, 0, 2);
        
        byte[] targetPortBytes = BitConverter.GetBytes(targetPort);
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
    
    public static byte[] GetRawIpWrapper(IPAddress sourceIpAddress, IPAddress targetIpAddress, ushort targetPort, ushort sourcePort)
    {
        byte[] ipHeaderBytes = ConvertHexToByteArray("4500002c2680000034067ecc");
        byte[] sourceIpBytes = sourceIpAddress.GetAddressBytes();
        byte[] targetIpBytes = targetIpAddress.GetAddressBytes();
        
        byte[] tcpSynPacketBytes = GetTcpSynPacketBytes(targetPort, sourcePort);
        byte[] packetBytes = new byte[ipHeaderBytes.Length + tcpSynPacketBytes.Length + sourceIpBytes.Length + targetIpBytes.Length];
        ipHeaderBytes.CopyTo(packetBytes, 0);
        sourceIpBytes.CopyTo(packetBytes, ipHeaderBytes.Length);
        targetIpBytes.CopyTo(packetBytes, ipHeaderBytes.Length + sourceIpBytes.Length);
        tcpSynPacketBytes.CopyTo(packetBytes, ipHeaderBytes.Length + sourceIpBytes.Length + targetIpBytes.Length);
        return packetBytes;
    }
    
    private static byte[] ConvertHexToByteArray(string hexString)
    {
        int length = hexString.Length;
        byte[] byteArray = new byte[length / 2];

        for (int i = 0; i < length; i += 2)
        {
            byteArray[i / 2] = (byte)((GetHexValue(hexString[i]) << 4) | GetHexValue(hexString[i + 1]));
        }

        return byteArray;
    }
    
    private static int GetHexValue(char hexDigit)
    {
        int value = hexDigit - '0';
        return value > 9 ? value - 7 : value;
    }
}
