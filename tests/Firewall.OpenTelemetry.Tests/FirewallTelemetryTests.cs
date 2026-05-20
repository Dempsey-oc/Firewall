using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Linq;
using FluentAssertions;
using Xunit;

namespace Firewall.OpenTelemetry.Tests;

/// <summary>
/// Behavioural tests for <see cref="FirewallTelemetry"/>. We attach a real
/// <see cref="MeterListener"/> and <see cref="ActivityListener"/>, then drive
/// the adapter and assert that the right instruments/spans appear with the
/// right tags.
/// </summary>
public sealed class FirewallTelemetryTests
{
    [Fact]
    public void Sentinel_constants_are_stable()
    {
        FirewallTelemetry.ActivitySourceName.Should().Be("Firewall");
        FirewallTelemetry.MeterName.Should().Be("Firewall");
    }

    [Fact]
    public void RecordDecision_emits_evaluation_counter_with_rule_name_tag()
    {
        using var collector = new MetricsCollector();
        var sut = new FirewallTelemetry();

        sut.RecordDecision("IpAllow", RuleDecision.Allow, elapsedMilliseconds: 0.123);

        var sample = collector.Counters["firewall.requests.evaluated"].Should()
            .ContainSingle().Subject;
        sample.Value.Should().Be(1);
        sample.Tags.Should().ContainKey("firewall.rule.name").WhoseValue.Should().Be("IpAllow");
    }

    [Fact]
    public void RecordDecision_emits_decision_counter_with_decision_tag()
    {
        using var collector = new MetricsCollector();
        var sut = new FirewallTelemetry();

        sut.RecordDecision("IpDeny", RuleDecision.Deny, elapsedMilliseconds: 5);

        var sample = collector.Counters["firewall.requests.decisions"].Should()
            .ContainSingle().Subject;
        sample.Tags.Should().ContainKey("firewall.decision").WhoseValue.Should().Be("Deny");
    }

    [Fact]
    public void RecordDecision_emits_duration_histogram_with_rule_and_decision_tags()
    {
        using var collector = new MetricsCollector();
        var sut = new FirewallTelemetry();

        sut.RecordDecision("CidrAllow", RuleDecision.Continue, elapsedMilliseconds: 1.5);

        var sample = collector.Histograms["firewall.evaluation.duration"].Should()
            .ContainSingle().Subject;
        sample.Value.Should().Be(1.5);
        sample.Tags.Should().ContainKey("firewall.rule.name").WhoseValue.Should().Be("CidrAllow");
        sample.Tags.Should().ContainKey("firewall.decision").WhoseValue.Should().Be("Continue");
    }

    [Fact]
    public void RecordProviderRefresh_emits_refresh_histogram_with_provider_and_success_tags()
    {
        using var collector = new MetricsCollector();
        var sut = new FirewallTelemetry();

        sut.RecordProviderRefresh("cloudflare", succeeded: true, elapsedMilliseconds: 123.45);

        var sample = collector.Histograms["firewall.provider.refresh.duration"].Should()
            .ContainSingle().Subject;
        sample.Value.Should().Be(123.45);
        sample.Tags.Should().ContainKey("firewall.provider").WhoseValue.Should().Be("cloudflare");
        sample.Tags.Should().ContainKey("firewall.refresh.succeeded").WhoseValue.Should().Be(true);
    }

    [Fact]
    public void StartEvaluationActivity_returns_null_when_no_listener_is_attached()
    {
        var sut = new FirewallTelemetry();
        sut.StartEvaluationActivity("AnyRule").Should().BeNull();
    }

    [Fact]
    public void StartEvaluationActivity_creates_an_activity_tagged_with_rule_name_when_listener_attached()
    {
        using var collector = new ActivityCollector();
        var sut = new FirewallTelemetry();

        using (var activity = sut.StartEvaluationActivity("CountryAllow"))
        {
            activity.Should().NotBeNull();
            activity!.OperationName.Should().Be("firewall.rule.evaluate");
            activity.GetTagItem("firewall.rule.name").Should().Be("CountryAllow");
        }

        collector.Started.Should().Contain(a => a.OperationName == "firewall.rule.evaluate");
        collector.Stopped.Should().Contain(a => a.OperationName == "firewall.rule.evaluate");
    }

    /// <summary>
    /// Captures meter measurements for the duration of the test. Subscribes to
    /// the Firewall meter only so we don't pollute results with unrelated
    /// instruments from other tests.
    /// </summary>
    private sealed class MetricsCollector : IDisposable
    {
        private readonly MeterListener _listener;

        public Dictionary<string, List<Measurement>> Counters { get; } = new(StringComparer.Ordinal);
        public Dictionary<string, List<Measurement>> Histograms { get; } = new(StringComparer.Ordinal);

        public MetricsCollector()
        {
            _listener = new MeterListener
            {
                InstrumentPublished = (instrument, listener) =>
                {
                    if (instrument.Meter.Name == FirewallTelemetry.MeterName)
                        listener.EnableMeasurementEvents(instrument);
                },
            };

            _listener.SetMeasurementEventCallback<long>(OnLong);
            _listener.SetMeasurementEventCallback<double>(OnDouble);
            _listener.Start();
        }

        private void OnLong(Instrument instrument, long value, ReadOnlySpan<KeyValuePair<string, object?>> tags, object? state)
            => Append(Counters, instrument, value, tags);

        private void OnDouble(Instrument instrument, double value, ReadOnlySpan<KeyValuePair<string, object?>> tags, object? state)
            => Append(Histograms, instrument, value, tags);

        private static void Append(Dictionary<string, List<Measurement>> bag, Instrument instrument, double value, ReadOnlySpan<KeyValuePair<string, object?>> tags)
        {
            if (!bag.TryGetValue(instrument.Name, out var list))
            {
                list = new List<Measurement>();
                bag[instrument.Name] = list;
            }

            var dict = new Dictionary<string, object?>(StringComparer.Ordinal);
            foreach (var t in tags) dict[t.Key] = t.Value;
            list.Add(new Measurement(value, dict));
        }

        public void Dispose() => _listener.Dispose();
    }

    private sealed record Measurement(double Value, IReadOnlyDictionary<string, object?> Tags);

    /// <summary>
    /// Captures activities started under the Firewall ActivitySource for the
    /// duration of the test.
    /// </summary>
    private sealed class ActivityCollector : IDisposable
    {
        private readonly ActivityListener _listener;

        public List<Activity> Started { get; } = new();
        public List<Activity> Stopped { get; } = new();

        public ActivityCollector()
        {
            _listener = new ActivityListener
            {
                ShouldListenTo = s => s.Name == FirewallTelemetry.ActivitySourceName,
                Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllData,
                ActivityStarted = a => Started.Add(a),
                ActivityStopped = a => Stopped.Add(a),
            };
            ActivitySource.AddActivityListener(_listener);
        }

        public void Dispose() => _listener.Dispose();
    }
}

internal static class DictExtensions
{
    public static IReadOnlyDictionary<string, object?> ToReadOnlyDict(this IEnumerable<KeyValuePair<string, object?>> kvps)
    {
        var d = new Dictionary<string, object?>(StringComparer.Ordinal);
        foreach (var k in kvps) d[k.Key] = k.Value;
        return d;
    }
}
