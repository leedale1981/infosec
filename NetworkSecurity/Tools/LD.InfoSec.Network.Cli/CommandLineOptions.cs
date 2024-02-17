using CommandLine;

namespace LD.InfoSec.Network.Cli;

public class CommandLineOptions
{
    [Value(index: 0, Required = true, HelpText="Network action to execute. DoS, Discover, Scan")]
    public string Action { get; set; }

    [Option(shortName: 't', longName: "target", Required = true, HelpText = "IP address of target")]
    public string TargetIp { get; set; }
    
    [Option(shortName: 'p', longName: "port", Required = false, HelpText = "Port on target")]
    public string TargetPort { get; set; }
    
    [Option(shortName: 's', longName: "source", Required = false, HelpText = "IP address of source")]
    public string SourceIp { get; set; }
}