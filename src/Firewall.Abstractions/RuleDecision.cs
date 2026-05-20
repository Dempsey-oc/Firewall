namespace Firewall;

/// <summary>
/// The terminal decision a rule may return after evaluating a request.
/// </summary>
/// <remarks>
/// <para><see cref="Allow"/> short-circuits the pipeline and admits the request.</para>
/// <para><see cref="Deny"/> short-circuits the pipeline and rejects the request.</para>
/// <para><see cref="Continue"/> defers to the next rule.</para>
/// </remarks>
public enum RuleDecision : byte
{
    /// <summary>The rule did not match; the next rule should evaluate.</summary>
    Continue = 0,

    /// <summary>The rule matched and the request is admitted. The pipeline short-circuits.</summary>
    Allow = 1,

    /// <summary>The rule matched and the request is rejected. The pipeline short-circuits.</summary>
    Deny = 2,
}
