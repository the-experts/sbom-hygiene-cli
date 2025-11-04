package nl.theexperts.sbom.dependencyvalidator;

import nl.theexperts.sbom.dependencyvalidator.model.*;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class DependencyValidator {

    private final RuleEngine ruleEngine;

    public DependencyValidator(RuleEngine ruleEngine) {
        this.ruleEngine = ruleEngine;
    }

    public ValidationSummary validate(
            List<Dependency> dependencies,
            Path validationRulesOverridePath,
            Path licenseRulesOverridePath,
            Path failureRulesOverridePath
    ) {
        ValidationRules validationRules = RulesLoader.loadValidationRules(validationRulesOverridePath);
        LicenseRules licenseRules = RulesLoader.loadLicenseRules(licenseRulesOverridePath);
        FailureRules failureRules = RulesLoader.loadFailureRules(failureRulesOverridePath);

        return ruleEngine.evaluate(
                dependencies,
                validationRules,
                licenseRules,
                failureRules
        );
    }

    public List<RuleFinding> validate(Dependency dep, List<DependencyRule> rules) {
        List<RuleFinding> results = new ArrayList<>();

        for (DependencyRule rule : rules) {
            // Apply each rule to the dependency and collect results
            RuleFinding result = checkRule(dep, rule);
            results.add(result);
        }

        return results;
    }

    private RuleFinding checkRule(Dependency dep, DependencyRule rule) {
        Dependency.Score s = dep.score();
        List<String> errors = new ArrayList<>();

        // Implement rule checking logic here
        return new RuleFinding(dep, rule, errors);
    }
}
