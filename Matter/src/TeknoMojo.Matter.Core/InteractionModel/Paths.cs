namespace TeknoMojo.Matter.Core.InteractionModel;

/// <summary>An attribute path (endpoint/cluster/attribute), with wildcards represented as null.</summary>
public sealed record AttributePath(uint? Endpoint, uint? Cluster, uint? Attribute, uint? ListIndex = null)
{
    public static AttributePath Exact(uint endpoint, uint cluster, uint attribute) => new(endpoint, cluster, attribute);
}

/// <summary>A command path (endpoint/cluster/command) — always fully specified for Invoke.</summary>
public sealed record CommandPath(uint Endpoint, uint Cluster, uint Command);

/// <summary>One command invocation: its path plus TLV-encoded command fields (a Structure, possibly empty).</summary>
public sealed record CommandInvocation(CommandPath Path, byte[] FieldsTlv);

/// <summary>Result of one command invocation: either data (a response payload) or a bare status.</summary>
public abstract record InvokeResult
{
    public sealed record Data(CommandPath Path, byte[] FieldsTlv) : InvokeResult;
    public sealed record Status(CommandPath Path, MatterStatus Status_, uint? ClusterStatus = null) : InvokeResult;
}

/// <summary>One attribute read result: either data (the value, TLV-encoded) or a status (e.g. UnsupportedAttribute).</summary>
public abstract record AttributeReport
{
    public sealed record Data(AttributePath Path, byte[] ValueTlv, uint? DataVersion = null) : AttributeReport;
    public sealed record Status(AttributePath Path, MatterStatus Status_, uint? ClusterStatus = null) : AttributeReport;
}
