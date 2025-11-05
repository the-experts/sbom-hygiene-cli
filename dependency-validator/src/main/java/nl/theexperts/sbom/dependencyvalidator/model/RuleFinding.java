package nl.theexperts.sbom.dependencyvalidator.model;

import java.util.List;

public record RuleFinding(
        Dependency dependency,
        String ruleId,
        RuleCategory ruleCategory,
        RuleOutcome outcome,
        List<String> messages) {
    public boolean isPassed() {
        return outcome == RuleOutcome.PASS;
    }
}