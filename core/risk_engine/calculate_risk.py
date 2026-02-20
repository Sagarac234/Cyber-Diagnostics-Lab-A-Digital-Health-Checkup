import json
import os


class RiskEngine:
    """
    Risk calculation and OWASP/CVSS mapping engine.
    Converts findings into risk scores and categorizes by OWASP Top 10.
    """
    
    # OWASP Top 10 2021 Mapping
    OWASP_CATEGORIES = {
        "A01": "Broken Access Control",
        "A02": "Cryptographic Failures",
        "A03": "Injection",
        "A04": "Insecure Design",
        "A05": "Security Misconfiguration",
        "A06": "Vulnerable and Outdated Components",
        "A07": "Authentication Failures",
        "A08": "Software and Data Integrity Failures",
        "A09": "Logging and Monitoring Failures",
        "A10": "Server-Side Request Forgery (SSRF)"
    }
    
    # Severity to CVSS Score mapping
    SEVERITY_SCORES = {
        "critical": 9.0,
        "high": 7.0,
        "medium": 5.0,
        "low": 3.0,
        "info": 0.1
    }
    
    def __init__(self, scan_results):
        self.scan_results = scan_results
        self.findings_list = []
        self.risk_summary = {}
        
    def calculate_risk(self):
        """Main risk calculation method."""
        self._extract_findings()
        self._categorize_by_owasp()
        self._calculate_overall_score()
        
        return {
            "overall_score": self.risk_summary.get("overall_score", 0),
            "severity_breakdown": self._get_severity_breakdown(),
            "owasp_mapping": self._get_owasp_mapping(),
            "risk_level": self._get_risk_level(),
            "recommendations": self._get_recommendations()
        }
    
    def _extract_findings(self):
        """Extract all findings from scan results."""
        for module_key, module_result in self.scan_results.items():
            if module_key == "metadata":
                continue
            
            if isinstance(module_result, dict) and "findings" in module_result:
                for finding in module_result["findings"]:
                    finding["module"] = module_key
                    finding["cvss_score"] = self.SEVERITY_SCORES.get(
                        finding.get("severity", "info").lower(), 0
                    )
                    self.findings_list.append(finding)
    
    def _categorize_by_owasp(self):
        """Map findings to OWASP Top 10 categories."""
        self.owasp_mapping = {owasp: {"findings": [], "count": 0} for owasp in self.OWASP_CATEGORIES}
        
        # Mapping logic for findings to OWASP categories
        category_keywords = {
            "A01": ["access", "permission", "authentication", "authorization", "broken auth"],
            "A02": ["ssl", "tls", "encryption", "cryptograph", "certificate", "password"],
            "A03": ["injection", "sql", "command", "ldap", "xss"],
            "A04": ["design", "flaw", "architecture", "threat model"],
            "A05": ["misconfiguration", "config", "default", "debug", "headers", "ports"],
            "A06": ["vulnerable", "outdated", "component", "library", "framework", "version", "cve", "plugin"],
            "A07": ["session", "mfa", "password", "credential", "factor authentication"],
            "A08": ["integrity", "signing", "serialization", "dependency", "artifact"],
            "A09": ["logging", "monitoring", "detection", "alerting"],
            "A10": ["ssrf", "request forgery", "redirect"]
        }
        
        for finding in self.findings_list:
            finding_text = (finding.get("title", "") + " " + finding.get("description", "")).lower()
            
            mapped = False
            for owasp_code, keywords in category_keywords.items():
                if any(keyword in finding_text for keyword in keywords):
                    self.owasp_mapping[owasp_code]["findings"].append(finding)
                    self.owasp_mapping[owasp_code]["count"] += 1
                    mapped = True
                    break
            
            # Default mapping if no category matched
            if not mapped:
                self.owasp_mapping["A05"]["findings"].append(finding)
                self.owasp_mapping["A05"]["count"] += 1
    
    def _calculate_overall_score(self):
        """Calculate overall CVSS-like score (0-10 scale)."""
        if not self.findings_list:
            self.risk_summary["overall_score"] = 0
            return
        
        # Weight critical findings more heavily
        weighted_sum = 0
        for finding in self.findings_list:
            severity = finding.get("severity", "info").lower()
            weight = 1.5 if severity == "critical" else 1.0
            weighted_sum += self.SEVERITY_SCORES.get(severity, 0) * weight
        
        # Calculate average with weighting
        average_score = weighted_sum / (len(self.findings_list) * 1.25)
        
        # Cap at 10
        self.risk_summary["overall_score"] = min(average_score, 10.0)
    
    def _get_severity_breakdown(self):
        """Get count of findings by severity."""
        breakdown = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        }
        
        for finding in self.findings_list:
            severity = finding.get("severity", "info").lower()
            if severity in breakdown:
                breakdown[severity] += 1
        
        return breakdown
    
    def _get_owasp_mapping(self):
        """Get OWASP Top 10 mapping with findings count."""
        mapping = {}
        for code, category_name in self.OWASP_CATEGORIES.items():
            count = self.owasp_mapping[code]["count"]
            mapping[code] = {
                "name": category_name,
                "count": count,
                "findings": [
                    {
                        "title": f["title"],
                        "severity": f["severity"],
                        "module": f["module"]
                    } for f in self.owasp_mapping[code]["findings"][:3]  # Top 3
                ]
            }
        
        return mapping
    
    def _get_risk_level(self):
        """Determine overall risk level."""
        score = self.risk_summary.get("overall_score", 0)
        
        if score >= 8:
            return "Critical"
        elif score >= 6:
            return "High"
        elif score >= 4:
            return "Medium"
        elif score >= 2:
            return "Low"
        else:
            return "Minimal"
    
    def _get_recommendations(self):
        """Get top recommendations based on findings."""
        recommendations = []
        
        # Get critical findings first
        critical_findings = [f for f in self.findings_list if f.get("severity", "").lower() == "critical"]
        high_findings = [f for f in self.findings_list if f.get("severity", "").lower() == "high"]
        
        # Add remediation recommendations
        for finding in critical_findings[:5]:  # Top 5 critical
            recommendations.append({
                "priority": "CRITICAL",
                "finding": finding.get("title"),
                "action": finding.get("remediation", "Address immediately")
            })
        
        for finding in high_findings[:5]:  # Top 5 high
            recommendations.append({
                "priority": "HIGH",
                "finding": finding.get("title"),
                "action": finding.get("remediation", "Address as soon as possible")
            })
        
        return recommendations
