from typing import Dict, Any
import re

class Rule:
    def __init__(self, name: str, description: str, condition: str, action: str):
        self.name = name
        self.description = description
        self.condition = condition
        self.action = action

    def evaluate(self, log: Dict[str, Any]) -> bool:
        try:
            return eval(self.condition, {}, {"log": log})
        except Exception as e:
            print(f"Error evaluating rule {self.name}: {e}")
            return False

class RuleEngine:
    def __init__(self):
        self.rules = []

    def add_rule(self, rule: Rule):
        self.rules.append(rule)

    def evaluate_log(self, log: Dict[str, Any]) -> list:
        triggered_rules = []
        for rule in self.rules:
            if rule.evaluate(log):
                triggered_rules.append(rule)
        return triggered_rules

# Example rules
example_rules = [
    Rule(
        name="High CPU Usage",
        description="Detects if CPU usage is above 90%",
        condition="log.get('system_logs', {}).get('cpu_usage', 0) > 90",
        action="alert"
    ),
    Rule(
        name="Suspicious External Traffic",
        description="Detects external traffic to known malicious IPs",
        condition="any(ip in log.get('external_logs', {}).get('destination_ips', []) for ip in ['192.168.1.100', '10.0.0.1'])",
        action="block"
    )
]

# Initialize rule engine with example rules
rule_engine = RuleEngine()
for rule in example_rules:
    rule_engine.add_rule(rule)
