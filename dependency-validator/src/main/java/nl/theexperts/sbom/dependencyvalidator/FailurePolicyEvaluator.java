package nl.theexperts.sbom.dependencyvalidator;

import nl.theexperts.sbom.dependencyvalidator.model.FailureEvaluationResult;
import nl.theexperts.sbom.dependencyvalidator.model.FailureRules;
import nl.theexperts.sbom.dependencyvalidator.model.RuleFinding;
import nl.theexperts.sbom.dependencyvalidator.model.RuleOutcome;

import java.util.List;

public class FailurePolicyEvaluator {

    public static FailureEvaluationResult evaluate(
            List<RuleFinding> findings,
            FailureRules failureRules
    ) {
        var cfg = failureRules.getRules();

        // baseline: weighted scoring later
        double score = 100.0;

        long fails = findings.stream()
                .filter(f -> f.outcome() == RuleOutcome.FAIL)
                .count();

        boolean success = fails == 0;

        return new FailureEvaluationResult(success, score);
    }
}
