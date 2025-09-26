using QuantCrypt.Core.Math;

namespace QuantCrypt.Core.Tests;

public class MathTests
{
    [Fact]
    public void ModPolynomial_Add_Successful_Test()
    {
        // Arrange
        Polynomial[] polynomialA = new[]
        {
            new Polynomial(2, 4),
            new Polynomial(3, 3),
            new Polynomial(10, 1),
            new Polynomial(3, 0)
        };

        Polynomial[] polynomialB = new[]
        {
            new Polynomial(3, 5),
            new Polynomial(14, 3),
            new Polynomial(10, 1),
            new Polynomial(4, 0)
        };

        // Act
        Polynomial[] actualResult = PolynomialOperations.AddMod(polynomialA, polynomialB, 17);
        
        // Assert
        Polynomial[] expectedResult = new[]
        {
            new Polynomial(3, 5),
            new Polynomial(2, 4),
            new Polynomial(3, 1),
            new Polynomial(7, 0)
        };
        expectedResult.OrderByDescending(p => p.Order);

        Assert.True(expectedResult.SequenceEqual(actualResult));
    }
}
