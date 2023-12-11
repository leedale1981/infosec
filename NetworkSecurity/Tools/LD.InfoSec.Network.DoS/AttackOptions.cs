namespace LD.InfoSec.Network.DoS;

public class AttackOptions
{
    public string TargetIp { get; set; }
    public UInt16 TargetPort { get; set; }
    public UInt16 SourcePort { get; set; }
    public DosType DosType { get; set; }
    public int Size { get; set; }
}