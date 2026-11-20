namespace TeknoMojo.HomeKit.Hap;

/// <summary>Setup code wrong, signature mismatch, or unexpected peer identity during pairing.</summary>
public class HapAuthenticationException : Exception
{
    public HapAuthenticationException(string message) : base(message) { }
}

/// <summary>Malformed HAP protocol response, unexpected state, or HTTP error from the accessory.</summary>
public class HapProtocolException : Exception
{
    public HapProtocolException(string message) : base(message) { }
}
