package nl.theexperts.sbom.api.validation;

import java.util.List;

public record ValidationSummary(
        boolean success,
        double score,
        List<RuleFinding> findings
) {}
