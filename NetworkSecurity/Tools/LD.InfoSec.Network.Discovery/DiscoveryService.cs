using LD.InfoSec.Network.Linux;
using LD.InfoSec.Network.Shared;

namespace LD.InfoSec.Network.Discovery;

public class DiscoveryService(DiscoveryOptions options)
{
    public async Task Start()
    {
        if (options.DiscoveryType == DiscoveryType.PingSweep)
        {
            await StartPingSweep();
        }
    }

    private async Task StartPingSweep()
    {
        List<string> ips = new();
        
        if (options.TargetIp.Contains('/'))
        {
            ips = GetIpsFromCidr(options.TargetIp);    
        }

        ips = options.TargetIp.Contains('-') ? GetIpsFromRange(options.TargetIp) : [options.TargetIp];

        foreach (string ip in ips)
        {
            byte echoType = GetEchoType(options.IcmpType);
            string response = await Shared.NetworkService.SendIcmpPackets(ip, echoType);
        }
    }

    private byte GetEchoType(IcmpType optionsIcmpType)
    {
        return optionsIcmpType switch
        {
            IcmpType.EchoRequest => 8,
            IcmpType.EchoReply => 0,
            _ => 8
        };
    }

    private List<string> GetIpsFromRange(string optionsTargetIp)
    {
        List<string> ips = new();
        
        string[] parts = optionsTargetIp.Split('-');
        string startIp = parts[0];
        string endIp = parts[1];
        
        string[] startIpParts = startIp.Split('.');
        string[] endIpParts = endIp.Split('.');
        
        int[] startIpNumbers = new int[4];
        int[] endIpNumbers = new int[4];
        
        for (int i = 0; i < 4; i++)
        {
            startIpNumbers[i] = int.Parse(startIpParts[i]);
            endIpNumbers[i] = int.Parse(endIpParts[i]);
        }
        
        for (int i = startIpNumbers[0]; i <= endIpNumbers[0]; i++)
        {
            for (int j = startIpNumbers[1]; j <= endIpNumbers[1]; j++)
            {
                for (int k = startIpNumbers[2]; k <= endIpNumbers[2]; k++)
                {
                    for (int l = startIpNumbers[3]; l <= endIpNumbers[3]; l++)
                    {
                        ips.Add($"{i}.{j}.{k}.{l}");
                    }
                }
            }
        }
        
        return ips;
    }

    private List<string> GetIpsFromCidr(string optionsTargetIp)
    {
        List<string> ips = new();
        
        string[] parts = optionsTargetIp.Split('/');
        string ip = parts[0];
        int mask = int.Parse(parts[1]);
        
        string[] ipParts = ip.Split('.');
        int[] ipNumbers = new int[4];
        
        for (int i = 0; i < 4; i++)
        {
            ipNumbers[i] = int.Parse(ipParts[i]);
        }
        
        int[] maskNumbers = new int[4];
        
        for (int i = 0; i < 4; i++)
        {
            maskNumbers[i] = 0;
        }
        
        for (int i = 0; i < mask; i++)
        {
            maskNumbers[i / 8] |= (1 << (7 - i % 8));
        }
        
        int[] startIp = new int[4];
        
        for (int i = 0; i < 4; i++)
        {
            startIp[i] = ipNumbers[i] & maskNumbers[i];
        }
        
        int[] endIp = new int[4];
        
        for (int i = 0; i < 4; i++)
        {
            endIp[i] = ipNumbers[i] | ~maskNumbers[i];
        }
        
        for (int i = startIp[0]; i <= endIp[0]; i++)
        {
            for (int j = startIp[1]; j <= endIp[1]; j++)
            {
                for (int k = startIp[2]; k <= endIp[2]; k++)
                {
                    for (int l = startIp[3]; l <= endIp[3]; l++)
                    {
                        ips.Add($"{i}.{j}.{k}.{l}");
                    }
                }
            }
        }
        
        return ips;
    }
}
