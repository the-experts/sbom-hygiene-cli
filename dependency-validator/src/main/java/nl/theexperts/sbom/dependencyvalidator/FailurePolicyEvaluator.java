package nl.theexperts.sbom.dependencyvalidator;

import nl.theexperts.sbom.api.validation.FailureEvaluationResult;
import nl.theexperts.sbom.api.validation.FailureRules;
import nl.theexperts.sbom.api.validation.RuleFinding;
import nl.theexperts.sbom.api.validation.RuleOutcome;
import nl.theexperts.sbom.api.validation.RuleCategory;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

public class FailurePolicyEvaluator {

    public static FailureEvaluationResult evaluate(
            List<RuleFinding> findings,
            FailureRules failureRules
    ) {
        var cfg = failureRules.getRules();

        // default score (100 == perfect)
        double score;

        if (findings == null) {
            findings = List.of();
        }

        // Unique dependencies analyzed
        Set<String> uniqueDeps = findings.stream()
                .map(f -> f.dependency() == null ? "" : (f.dependency().url() == null ? "" : f.dependency().url().toString()))
                .filter(s -> s != null && !s.isBlank())
                .collect(Collectors.toSet());

        int uniqueCount = uniqueDeps.size();

        // Quick checks: missing metadata or API error
        if (cfg.isFailOnMissingMetadata()) {
            boolean anyMissing = findings.stream()
                    .map(RuleFinding::dependency)
                    .anyMatch(d -> d == null || d.score() == null);
            if (anyMissing) {
                return new FailureEvaluationResult(false, 0.0);
            }
        }

        if (cfg.isFailOnApiError()) {
            boolean anyApiError = findings.stream()
                    .flatMap(f -> f.messages().stream())
                    .anyMatch(m -> m != null && m.toLowerCase().contains("api error"));
            if (anyApiError) {
                return new FailureEvaluationResult(false, 0.0);
            }
        }

        // Severity weights from config (error, warning, info)
        Map<String, Double> severityWeights = cfg.getRuleSeverityWeights();
        double weightError = severityWeights != null && severityWeights.containsKey("error") ? severityWeights.get("error") : 1.0;
        double weightWarning = severityWeights != null && severityWeights.containsKey("warning") ? severityWeights.get("warning") : 0.5;
        double weightInfo = severityWeights != null && severityWeights.containsKey("info") ? severityWeights.get("info") : 0.0;

        // Rule group weights
        Map<String, FailureRules.RuleGroup> groups = cfg.getRuleGroups();

        // Helper: map RuleOutcome -> severity weight
        Function<RuleOutcome, Double> outcomeToSeverity = o ->
            switch (o) {
                case FAIL -> weightError;
                case WARN -> weightWarning;
                case INFO -> weightInfo;
                case PASS -> 0.0;
            };

        // Helper: map RuleCategory to rule-group key (best-effort)
        java.util.function.Function<RuleCategory, String> categoryToGroup = c -> {
            if (c == null) return null;
            return switch (c) {
                case LICENSE -> "license-compliance";
                case VALIDATION -> "security";
                case FAILURE_POLICY -> "sustainability";
            };
        };

        // Compute total bad score and max possible bad score
        double totalBad = 0.0;
        double maxBad = 0.0;

        for (RuleFinding f : findings) {
            RuleOutcome outcome = f.outcome();
            double sev = outcomeToSeverity.apply(outcome);
            if (sev <= 0.0) {
                // no negative contribution for PASS or info (if configured)
                continue;
            }

            String groupKey = categoryToGroup.apply(f.ruleCategory());
            double groupWeight = 1.0;
            if (groups != null && groupKey != null && groups.containsKey(groupKey)) {
                groupWeight = groups.get(groupKey).getWeight();
            }

            totalBad += sev * groupWeight;
            maxBad += groupWeight; // max per finding assumes worst case severity == 1.0
        }

        double normalizedBad = (maxBad > 0.0) ? (totalBad / maxBad) : 0.0;
        score = (1.0 - normalizedBad) * 100.0;

        // evaluation-mode can be used later; for now weighted-average supported
        int threshold = cfg.getFailBuildAtPercentage();
        boolean success = Double.isFinite(score) && score >= threshold;

        // clamp score
        if (score < 0.0) score = 0.0;
        if (score > 100.0) score = 100.0;

        return new FailureEvaluationResult(success, Math.round(score * 100.0) / 100.0);
    }
}
