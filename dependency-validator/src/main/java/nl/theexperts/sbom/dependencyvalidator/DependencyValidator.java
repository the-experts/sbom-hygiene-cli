package nl.theexperts.sbom.dependencyvalidator;

import nl.theexperts.sbom.dependencyvalidator.model.*;

import java.nio.file.Path;
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
}
