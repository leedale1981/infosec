using System.Security.Cryptography;

if (MLKem.IsSupported)
{
    Console.WriteLine("ML-KEM is supported :)");
}
else
{
    Console.WriteLine("ML-KEM isn't supported :(");
    return;
}

Console.WriteLine("Testing ML-KEM 768...");
MLKemAlgorithm alg = MLKemAlgorithm.MLKem768;

Console.WriteLine("Generating key pairs...");
using MLKem privateKey = MLKem.GenerateKey(alg);
using MLKem publicKey = MLKem.ImportEncapsulationKey(alg, privateKey.ExportEncapsulationKey());

Console.WriteLine("Generating shared secret as ciphertext...");
publicKey.Encapsulate(out byte[] ciphertext, out byte[] sharedSecret1);

Console.WriteLine("Decrypting ciphertext with private key...");
byte[] sharedSecret2 = privateKey.Decapsulate(ciphertext);

Console.WriteLine("Checking shared secrets match...");
if (sharedSecret1.AsSpan().SequenceEqual(sharedSecret2))
{
    Console.WriteLine($"Same answer, yay math! {Convert.ToHexString(sharedSecret1)}");
}
else
{
    Console.WriteLine("You just got the one in 2^165 failure. There's probably a prize for that.");
    Console.WriteLine($"sharedSecret1: {Convert.ToHexString(sharedSecret1)}");
    Console.WriteLine($"sharedSecret2: {Convert.ToHexString(sharedSecret2)}");
    Console.WriteLine($"MLKEM768 seed: {Convert.ToHexString(privateKey.ExportPrivateSeed())}");
}