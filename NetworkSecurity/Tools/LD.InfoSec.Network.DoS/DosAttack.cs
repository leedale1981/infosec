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
        bool linux = true;
        
        if (linux)
        {
            await Network.Linux.NetworkService.SendSynPackets(options.TargetIp, options.TargetPort, options.SourceIp, options.SourcePort, options.Size);
        }
    }
}
