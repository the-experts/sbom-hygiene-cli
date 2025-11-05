package nl.theexperts.sbom.api.validation;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Map;

public class ValidationRules {

    @JsonProperty
    private Map<String, ValidationRuleCriteria> rules;

    public Map<String, ValidationRuleCriteria> getRules() {
        return rules;
    }
}
