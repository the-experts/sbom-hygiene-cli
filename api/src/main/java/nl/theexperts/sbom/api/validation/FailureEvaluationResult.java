package nl.theexperts.sbom.api.validation;

public record FailureEvaluationResult(boolean success, double score) {
}
