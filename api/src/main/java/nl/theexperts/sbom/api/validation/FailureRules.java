package nl.theexperts.sbom.api.validation;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Map;

public class FailureRules {

    @JsonProperty("failure-rules")
    private FailureCriteria rules;

    public FailureCriteria getRules() {
        return rules;
    }

    public static class FailureCriteria {
        @JsonProperty("fail-build-at-percentage")
        private int failBuildAtPercentage;

        @JsonProperty("min-dependencies-analyzed")
        private int minDependenciesAnalyzed;

        @JsonProperty("fail-on-missing-metadata")
        private boolean failOnMissingMetadata;

        @JsonProperty("fail-on-api-error")
        private boolean failOnApiError;

        @JsonProperty("rule-severity-weights")
        private Map<String, Double> ruleSeverityWeights;

        @JsonProperty("rule-groups")
        private Map<String, RuleGroup> ruleGroups;

        @JsonProperty("evaluation-mode")
        private String evaluationMode;

        // getters
        public int getFailBuildAtPercentage() { return failBuildAtPercentage; }
        public int getMinDependenciesAnalyzed() { return minDependenciesAnalyzed; }
        public boolean isFailOnMissingMetadata() { return failOnMissingMetadata; }
        public boolean isFailOnApiError() { return failOnApiError; }
        public Map<String, Double> getRuleSeverityWeights() { return ruleSeverityWeights; }
        public Map<String, RuleGroup> getRuleGroups() { return ruleGroups; }
        public String getEvaluationMode() { return evaluationMode; }
    }

    public static class RuleGroup {
        private double weight;

        public double getWeight() { return weight; }
    }
}
