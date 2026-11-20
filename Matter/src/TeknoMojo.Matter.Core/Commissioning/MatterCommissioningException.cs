namespace TeknoMojo.Matter.Core.Commissioning;

/// <summary>PASE authentication failed — most commonly a wrong setup code.</summary>
public sealed class MatterCommissioningException : Exception
{
    public MatterCommissioningException(string message) : base(message) { }
}
