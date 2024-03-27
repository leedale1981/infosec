using LD.InfoSec.Network.Discovery;
using LD.InfoSec.Network.DoS;

Console.WriteLine("Starting...");
// DosAttack attack = new(new()
// {
//     Size = 1,
//     DosType = DosType.SynFlood,
//     SourcePort = 60270,
//     TargetIp = "172.20.71.194",
//     SourceIp = "192.168.86.150",
//     TargetPort = 9999,
// });

//await attack.Start();

DiscoveryService discovery = new(new DiscoveryOptions
{
    DiscoveryType = DiscoveryType.PingSweep,
    IcmpType = IcmpType.EchoRequest,
    TargetIp = "172.17.111.61",
});

await discovery.Start();