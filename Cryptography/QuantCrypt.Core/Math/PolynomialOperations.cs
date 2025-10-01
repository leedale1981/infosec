namespace QuantCrypt.Core.Math;

public record PolynomialTerm(int Coefficient, int Order);

public static class PolynomialOperations
{
    public static PolynomialTerm[] AddMod(PolynomialTerm[] polynomialA, PolynomialTerm[] polynomialB, int mod)
    {
        return ModOperation(polynomialA, polynomialB, mod,
            (poly, orderMatchPoly) => (poly.Coefficient + orderMatchPoly.Coefficient) % mod);
    }
    
    public static PolynomialTerm[] SubtractMod(PolynomialTerm[] polynomialA, PolynomialTerm[] polynomialB, int mod)
    {
        return ModOperation(polynomialA, polynomialB, mod,
            (poly, orderMatchPoly) => (poly.Coefficient - orderMatchPoly.Coefficient) % mod);
    }
    
    private static PolynomialTerm[] ModOperation(
        PolynomialTerm[] polynomialA, PolynomialTerm[] polynomialB, int mod, Func<PolynomialTerm, PolynomialTerm?, int> operation)
    {
        List<PolynomialTerm> result = new();

        foreach (PolynomialTerm poly in polynomialA)
        {
            PolynomialTerm? orderMatchPoly = polynomialB.FirstOrDefault(p => p.Order == poly.Order);
            result.Add(orderMatchPoly is null ? 
                poly with { Coefficient = poly.Coefficient % mod } : 
                poly with { Coefficient = operation.Invoke(poly, orderMatchPoly)});
        }

        result.AddRange(polynomialB
            .Where(p => result.All(r => r.Order != p.Order))
            .Select(p => p with { Coefficient = p.Coefficient % mod }));
        
        return result
            .Where(p => p.Coefficient != 0)
            .OrderByDescending(p => p.Order).ToArray();
    }
}