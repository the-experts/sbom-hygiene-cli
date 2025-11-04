package nl.theexperts.sbom.dependencyvalidator;

import nl.theexperts.sbom.dependencyvalidator.model.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class RuleEngine {

    public ValidationSummary evaluate(
            List<Dependency> dependencies,
            ValidationRules validationRules,
            LicenseRules licenseRules,
            FailureRules failureRules
    ) {
        List<RuleFinding> findings = new ArrayList<>();

        for (Dependency dep : dependencies) {
            // Evaluate each dependency against the provided rules
            findings.addAll(applyValidationRules(dep, validationRules));
            findings.addAll(applyLicenseRules(dep, licenseRules));
        }

        FailureEvaluationResult eval = FailurePolicyEvaluator.evaluate(findings, failureRules);

        return new ValidationSummary(eval.success(), eval.score(), findings);
    }

    private List<RuleFinding> applyValidationRules(Dependency dep, ValidationRules validationRules) {
        List<RuleFinding> results = new ArrayList<>();

        validationRules.getRules().forEach((ruleId, criteria) -> {
            RuleFinding finding = applyValidationRule(dep, ruleId, criteria);
            results.add(finding);
        });

        return results;
    }

    private RuleFinding applyValidationRule(
            Dependency dep,
            String ruleId,
            ValidationRuleCriteria criteria
    ) {
        List<String> messages = new ArrayList<>();

        // Placeholder example rule: GitHub stars
        // ("github-stars" rule is present in your JSON!)
        if (criteria.get("metric") != null && criteria.get("metric").equals("stars")) {
            int stars = dep.score().stars();
            int warnAt = (int) criteria.get("warn-at");
            int failAt = (int) criteria.get("fail-at");

            if (stars < failAt) {
                messages.add("Stars below fail threshold: " + stars);
                return new RuleFinding(dep, ruleId, RuleCategory.VALIDATION, RuleOutcome.FAIL, messages);
            }
            if (stars < warnAt) {
                messages.add("Stars below warn threshold: " + stars);
                return new RuleFinding(dep, ruleId, RuleCategory.VALIDATION, RuleOutcome.WARN, messages);
            }
            return new RuleFinding(dep, ruleId, RuleCategory.VALIDATION, RuleOutcome.PASS, messages);
        }

        return new RuleFinding(dep, ruleId, RuleCategory.VALIDATION, RuleOutcome.WARN, List.of("Rule not implemented yet"));
    }

    private List<RuleFinding> applyLicenseRules(Dependency dep, LicenseRules rules) {
        List<RuleFinding> results = new ArrayList<>();

        // Example: license-enforcement policy
        var enforcement = (Map<String, String>) rules.getRules().get("license-enforcement");
        String licenseType = dep.metadata().licenseGroup(); // e.g. permissive / weak-copyleft / strong-copyleft
        String action = enforcement.get(licenseType);

        RuleOutcome outcome = switch (action) {
            case "allow" -> RuleOutcome.PASS;
            case "warn" -> RuleOutcome.WARN;
            case "fail" -> RuleOutcome.FAIL;
            default -> RuleOutcome.WARN;
        };

        results.add(new RuleFinding(
                dep,
                "license-enforcement",
                RuleCategory.LICENSE,
                outcome,
                List.of("License category: " + licenseType + ", policy: " + action)
        ));

        return results;
    }
}
