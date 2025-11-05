package nl.theexperts.sbom.dependencyvalidator.model;

import java.util.List;

public record ValidationSummary(
        boolean success,
        double score,
        List<RuleFinding> findings
) {}
