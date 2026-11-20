namespace TeknoMojo.Matter.Core.InteractionModel;

/// <summary>
/// Interaction Model protocol message opcodes (protocol id 0x0001). Verified against
/// project-chip/connectedhomeip src/protocols/interaction_model/Constants.h.
/// </summary>
public static class InteractionModelOpcodes
{
    public const byte StatusResponse = 0x01;
    public const byte ReadRequest = 0x02;
    public const byte SubscribeRequest = 0x03;
    public const byte SubscribeResponse = 0x04;
    public const byte ReportData = 0x05;
    public const byte WriteRequest = 0x06;
    public const byte WriteResponse = 0x07;
    public const byte InvokeCommandRequest = 0x08;
    public const byte InvokeCommandResponse = 0x09;
    public const byte TimedRequest = 0x0A;
}

/// <summary>
/// The interaction-model-revision value this stack advertises on every top-level IM message, at
/// context tag 0xFF. Verified against src/app/SpecificationDefinedRevisions.h.
/// </summary>
public static class InteractionModelRevision
{
    public const byte Tag = 0xFF;
    public const uint Revision = 12;
}
