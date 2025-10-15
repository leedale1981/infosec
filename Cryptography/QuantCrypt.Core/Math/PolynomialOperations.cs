namespace QuantCrypt.Core.Math;

public record PolynomialTerm(int Coefficient, int Order);

public static class PolynomialOperations
{
    public static PolynomialTerm[] AddMod(PolynomialTerm[] polynomialA, PolynomialTerm[] polynomialB, int mod)
    {
        return ModOperation(polynomialA, polynomialB, mod,
            (poly, orderMatchPoly) => Mod((poly.Coefficient + orderMatchPoly.Coefficient), mod),
            (poly) => Mod(poly.Coefficient, mod));
    }
    
    public static PolynomialTerm[] SubtractMod(PolynomialTerm[] polynomialA, PolynomialTerm[] polynomialB, int mod)
    {
        return ModOperation(polynomialA, polynomialB, mod,
            (poly, orderMatchPoly) => Mod((poly.Coefficient - orderMatchPoly.Coefficient), mod),
            (poly) => Mod(-poly.Coefficient, mod));
    }
    
    public static PolynomialTerm[] MultiplyMod(PolynomialTerm[] polynomialA, PolynomialTerm[] polynomialB, int mod)
    {
        return ModOperation(polynomialA, polynomialB, mod,
            (poly, orderMatchPoly) => Mod((poly.Coefficient * orderMatchPoly.Coefficient), mod),
            (poly) => Mod(poly.Coefficient, mod));
    }
    
    private static PolynomialTerm[] ModOperation(
        PolynomialTerm[] polynomialA, 
        PolynomialTerm[] polynomialB, 
        int mod, 
        Func<PolynomialTerm, PolynomialTerm?, int> operation, 
        Func<PolynomialTerm, int> noMatchOperation)
    {
        List<PolynomialTerm> result = new();

        foreach (PolynomialTerm poly in polynomialA)
        {
            PolynomialTerm? orderMatchPoly = polynomialB.FirstOrDefault(p => p.Order == poly.Order);
            result.Add(orderMatchPoly is null ? 
                poly with { Coefficient = Mod(poly.Coefficient, mod) } : 
                poly with { Coefficient = operation.Invoke(poly, orderMatchPoly)});
        }

        result.AddRange(polynomialB
            .Where(p => result.All(r => r.Order != p.Order))
            .Select(p => p with { Coefficient = noMatchOperation.Invoke(p) }));
        
        return result
            .Where(p => p.Coefficient != 0)
            .OrderByDescending(p => p.Order).ToArray();
    }

    private static int Mod(int a, int b)
    {
        return ((a % b) + b) % b;
    }
}