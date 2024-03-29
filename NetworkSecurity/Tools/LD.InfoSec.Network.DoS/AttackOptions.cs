﻿using LD.InfoSec.Network.Shared;

namespace LD.InfoSec.Network.DoS;

public class AttackOptions
{
    public string SourceIp { get; set; }
    public string TargetIp { get; set; }
    public UInt16 TargetPort { get; set; }
    public UInt16 SourcePort { get; set; }
    public DosType DosType { get; set; }
    public int Size { get; set; }
    public PlatformType PlatformType { get; set; }
}