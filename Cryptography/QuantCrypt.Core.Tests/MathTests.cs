using QuantCrypt.Core.Math;

namespace QuantCrypt.Core.Tests;

public class MathTests
{
    [Fact]
    public void ModPolynomial_Add_Successful_Test()
    {
        // Arrange
        PolynomialTerm[] polynomialA = new[]
        {
            new PolynomialTerm(2, 4),
            new PolynomialTerm(3, 3),
            new PolynomialTerm(10, 1),
            new PolynomialTerm(3, 0)
        };

        PolynomialTerm[] polynomialB = new[]
        {
            new PolynomialTerm(3, 5),
            new PolynomialTerm(14, 3),
            new PolynomialTerm(10, 1),
            new PolynomialTerm(4, 0)
        };

        // Act
        PolynomialTerm[] actualResult = PolynomialOperations.AddMod(polynomialA, polynomialB, 17);
        
        // Assert
        PolynomialTerm[] expectedResult = new[]
        {
            new PolynomialTerm(3, 5),
            new PolynomialTerm(2, 4),
            new PolynomialTerm(3, 1),
            new PolynomialTerm(7, 0)
        };
        expectedResult.OrderByDescending(p => p.Order);

        Assert.True(expectedResult.SequenceEqual(actualResult));
    }
}
