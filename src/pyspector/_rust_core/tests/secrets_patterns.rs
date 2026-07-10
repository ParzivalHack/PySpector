//! Table-driven tests for the built-in secret-detection rules
//! (`src/pyspector/rules/built-in-rules-secrets.toml`): one synthetic positive
//! fixture and one negative (must-not-match) fixture per rule id, plus a
//! check that redacted rules never store the raw secret verbatim.

use _rust_core::analysis::config_analysis::{compile_entropy_rules, scan_file, scan_file_entropy};
use _rust_core::rules::RuleSet;

const SECRETS_TOML: &str = include_str!("../../rules/built-in-rules-secrets.toml");

fn ruleset() -> RuleSet {
    toml::from_str(SECRETS_TOML).expect("built-in-rules-secrets.toml should parse")
}

struct Case {
    rule_id: &'static str,
    file_path: &'static str,
    positive: &'static str,
    negative: &'static str,
}

const CASES: &[Case] = &[
    Case {
        rule_id: "SEC-AWS-001",
        file_path: "config.py",
        // Split across concat! so the literal AWS-shaped key never appears
        // contiguous in source (avoids tripping GitHub push protection).
        positive: concat!("aws_key = \"AKIA", "ABCDEFGHIJKLMNOP\""),
        negative: "aws_key = \"AKIA123\"",
    },
    Case {
        rule_id: "SEC-AWS-002",
        file_path: "config.py",
        positive: concat!(
            "aws_secret_access_key = \"abcdefghijklmnopqrstuvwxyz",
            "ABCDEFGHIJ1234\""
        ),
        negative: "aws_secret_access_key = \"short\"",
    },
    Case {
        rule_id: "SEC-GCP-001",
        file_path: "config.json",
        positive: "\"type\": \"service_account\"",
        negative: "\"type\": \"authorized_user\"",
    },
    Case {
        rule_id: "SEC-GCP-002",
        file_path: "config.json",
        positive: "\"private_key\": \"-----BEGIN PRIVATE KEY-----FAKEKEYDATA-----END PRIVATE KEY-----\"", // pragma: allowlist secret
        negative: "\"other_key\": \"not-a-key\"",
    },
    Case {
        rule_id: "SEC-AZURE-001",
        file_path: "config.py",
        positive: "conn = \"DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=abcdEFGH1234567890abcdEFGH1234567890AB==\"",
        negative: "conn = \"DefaultEndpointsProtocol=https;AccountName=myaccount\"",
    },
    Case {
        rule_id: "SEC-GITHUB-001",
        file_path: "config.py",
        positive: "token = \"ghp_1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ\"", // pragma: allowlist secret
        negative: "token = \"ghp_short\"",
    },
    Case {
        rule_id: "SEC-SLACK-001",
        file_path: "config.py",
        positive: concat!(
            "token = \"xoxb-123456789012-1234567890123",
            "-abcdefghijklmnopqrstuvwx\"" // pragma: allowlist secret
        ),
        negative: "token = \"xoxb-short\"",
    },
    Case {
        rule_id: "SEC-STRIPE-001",
        file_path: "config.py",
        positive: concat!("key = \"sk_liv", "e_abcdefghijklmnopqrstuvwx1234\""), // pragma: allowlist secret
        negative: "key = \"sk_test_abcdefghijklmnopqrstuvwx1234\"", // pragma: allowlist secret
    },
    Case {
        rule_id: "SEC-PRIVATEKEY-001",
        file_path: "id_rsa",
        positive: "-----BEGIN RSA PRIVATE KEY-----", // pragma: allowlist secret
        negative: "-----BEGIN CERTIFICATE-----",
    },
    Case {
        rule_id: "SEC-JWT-001",
        file_path: "config.py",
        positive: "token = \"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PYb4LddY2Tm4\"", // pragma: allowlist secret
        negative: "token = \"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0\"", // pragma: allowlist secret
    },
    Case {
        rule_id: "SEC-GENERIC-001",
        file_path: "config.py",
        positive: "password = \"Sup3rSecretValue123\"",
        negative: "password = \"abc\"",
    },
];

#[test]
fn secret_patterns_match_positive_and_not_negative_fixtures() {
    let rs = ruleset();
    let known_ids: Vec<&str> = rs.rules.iter().map(|r| r.id.as_str()).collect();

    for case in CASES {
        assert!(
            known_ids.contains(&case.rule_id),
            "rule {} is not present in built-in-rules-secrets.toml (test/rule id drift)",
            case.rule_id
        );

        let pos_issues = scan_file(case.file_path, case.positive, &rs);
        assert!(
            pos_issues.iter().any(|i| i.rule_id == case.rule_id),
            "expected rule {} to match positive fixture: {:?}",
            case.rule_id,
            case.positive
        );

        let neg_issues = scan_file(case.file_path, case.negative, &rs);
        assert!(
            !neg_issues.iter().any(|i| i.rule_id == case.rule_id),
            "expected rule {} NOT to match negative fixture: {:?}",
            case.rule_id,
            case.negative
        );
    }
}

#[test]
fn redacted_rules_never_store_the_raw_secret_line() {
    let rs = ruleset();

    for case in CASES {
        let rule = rs
            .rules
            .iter()
            .find(|r| r.id == case.rule_id)
            .expect("rule must exist (checked in previous test)");

        if !rule.redact {
            continue;
        }

        let issues = scan_file(case.file_path, case.positive, &rs);
        let matches: Vec<_> = issues.iter().filter(|i| i.rule_id == case.rule_id).collect();
        assert!(!matches.is_empty(), "rule {} produced no issues", case.rule_id);

        for issue in matches {
            assert_ne!(
                issue.code, case.positive,
                "rule {} is marked redact=true but stored the raw, unredacted line",
                case.rule_id
            );
        }
    }
}

#[test]
fn entropy_rule_flags_random_token_but_not_repetitive_text() {
    let rs = ruleset();
    let compiled = compile_entropy_rules(&rs);
    assert!(!compiled.is_empty(), "expected at least one entropy_rule in built-in-rules-secrets.toml");

    let content_secret = "value = \"Zx9Qk3mP7vT2wL8dR4nC6yB1sA5jF0hE\"\n"; // pragma: allowlist secret
    let issues = scan_file_entropy("config.py", content_secret, &compiled, None);
    assert!(!issues.is_empty(), "expected entropy rule to flag a high-entropy token");
    assert!(
        !issues[0].code.contains("Zx9Qk3mP7vT2wL8dR4nC6yB1sA5jF0hE"),
        "entropy findings must be redacted"
    );

    let content_plain = "value = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n";
    let issues2 = scan_file_entropy("config.py", content_plain, &compiled, None);
    assert!(
        issues2.is_empty(),
        "expected entropy rule not to flag low-entropy repeated text"
    );
}
