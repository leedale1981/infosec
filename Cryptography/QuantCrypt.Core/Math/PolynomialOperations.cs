namespace QuantCrypt.Core.Math;

public record Polynomial(int Coefficient, int Order);

public static class PolynomialOperations
{
    public static Polynomial[] AddMod(Polynomial[] polynomialA, Polynomial[] polynomialB, int mod)
    {
        List<Polynomial> result = new();

        foreach (Polynomial poly in polynomialA)
        {
            Polynomial? orderMatchPoly = polynomialB.FirstOrDefault(p => p.Order == poly.Order);
            result.Add(orderMatchPoly is null ? 
                poly with { Coefficient = poly.Coefficient % mod } : 
                poly with { Coefficient = (poly.Coefficient + orderMatchPoly.Coefficient) % mod});
        }

        result.AddRange(polynomialB
            .Where(p => result.All(r => r.Order != p.Order))
            .Select(p => p with { Coefficient = p.Coefficient % mod }));
        
        return result
            .Where(p => p.Coefficient != 0)
            .OrderByDescending(p => p.Order).ToArray();
    }
}