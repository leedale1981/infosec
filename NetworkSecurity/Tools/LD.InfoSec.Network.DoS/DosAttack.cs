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
            await Linux.NetworkService.SendSynPackets(options.TargetIp, options.TargetPort, options.SourceIp, options.SourcePort, options.Size);
        }
    }
}
