using LD.InfoSec.Network.Shared;

namespace LD.InfoSec.Network.Discovery;

public class DiscoveryOptions
{
    public string TargetIp { get; set; }
    public IcmpType IcmpType { get; set; }
    public DiscoveryType DiscoveryType { get; set; }
    public PlatformType PlatformType { get; set; }
}