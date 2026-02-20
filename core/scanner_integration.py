"""
Master Security Scanner Integration
Orchestrates all security modules for comprehensive vulnerability assessment
"""

import json
from datetime import datetime
import sys
import os
# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.web_app_risk import WebAppRiskModule
from modules.security_config import SecurityConfigModule
from modules.owasp_coverage_analyzer import OWASPCoverageAnalyzer


class MasterSecurityScanner:
    """
    Comprehensive security scanner combining all modules
    """
    
    def __init__(self, target, rules=None):
        self.target = target
        self.rules = rules or {}
        self.findings = []
        self.modules_results = {}
    
    def execute_full_scan(self):
        """Execute comprehensive security scan across all modules."""
        print(f"\n{'='*80}")
        print(f"STARTING COMPREHENSIVE SECURITY SCAN: {self.target}")
        print(f"{'='*80}\n")
        
        # Module 1: Web Application Risk Analysis
        print("[1/3] Running Web Application Risk Analysis...")
        web_app_module = WebAppRiskModule(self.target, self.rules)
        web_app_results = web_app_module.execute()
        self.modules_results['web_app_risk'] = web_app_results
        self.findings.extend(web_app_results.get('findings', []))
        
        # Module 2: Security Configuration Analysis
        print("\n[2/3] Running Security Configuration Analysis...")
        security_config = SecurityConfigModule(self.target, self.rules)
        security_results = security_config.execute()
        self.modules_results['security_config'] = security_results
        self.findings.extend(security_results.get('findings', []))
        
        # Module 3: OWASP Top 10 Coverage Analysis
        print("\n[3/3] Running OWASP Top 10 Coverage Analysis...")
        owasp_module = OWASPCoverageAnalyzer(self.target, self.rules)
        owasp_results = owasp_module.execute()
        self.modules_results['owasp_coverage'] = owasp_results
        self.findings.extend(owasp_results.get('findings', []))
        
        return self.generate_final_report()
    
    def generate_final_report(self):
        """Generate comprehensive final report."""
        report = {
            "scan_metadata": {
                "target": self.target,
                "timestamp": datetime.now().isoformat(),
                "total_findings": len(self.findings),
                "modules_executed": list(self.modules_results.keys())
            },
            "severity_summary": self._get_severity_summary(),
            "findings_by_module": self._organize_findings_by_module(),
            "owasp_coverage": self._get_owasp_coverage(),
            "all_findings": self.findings
        }
        
        return report
    
    def _get_severity_summary(self):
        """Summarize findings by severity."""
        summary = {
            'critical': len([f for f in self.findings if f.get('severity') == 'critical']),
            'high': len([f for f in self.findings if f.get('severity') == 'high']),
            'medium': len([f for f in self.findings if f.get('severity') == 'medium']),
            'low': len([f for f in self.findings if f.get('severity') == 'low']),
            'info': len([f for f in self.findings if f.get('severity') == 'info'])
        }
        
        return summary
    
    def _organize_findings_by_module(self):
        """Organize findings by module."""
        organized = {}
        
        for module_name, module_result in self.modules_results.items():
            organized[module_name] = {
                'status': module_result.get('status'),
                'findings_count': len(module_result.get('findings', [])),
                'findings': module_result.get('findings', [])
            }
        
        return organized
    
    def _get_owasp_coverage(self):
        """Get OWASP Top 10 coverage summary."""
        owasp_data = self.modules_results.get('owasp_coverage', {})
        owasp_report = owasp_data.get('owasp_report', {})
        
        coverage_summary = {}
        for category, data in owasp_report.items():
            coverage_summary[category] = {
                'title': data.get('title'),
                'findings_count': data.get('findings_count', 0),
                'critical': data.get('critical', 0),
                'high': data.get('high', 0),
                'medium': data.get('medium', 0)
            }
        
        return coverage_summary
    
    def export_json_report(self, filename):
        """Export report to JSON file."""
        report = self.generate_final_report()
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n✅ Report exported to: {filename}")
        return filename
    
    def print_summary(self):
        """Print scan summary to console."""
        report = self.generate_final_report()
        
        print(f"\n{'='*80}")
        print(f"SECURITY SCAN SUMMARY: {self.target}")
        print(f"{'='*80}\n")
        
        # Severity Summary
        severity = report['severity_summary']
        print("📊 FINDINGS BY SEVERITY:")
        print(f"   🔴 Critical: {severity['critical']}")
        print(f"   🟠 High: {severity['high']}")
        print(f"   🟡 Medium: {severity['medium']}")
        print(f"   🔵 Low: {severity['low']}")
        print(f"   ⚪ Info: {severity['info']}")
        
        # OWASP Coverage
        print("\n📋 OWASP TOP 10 COVERAGE:")
        owasp = report['owasp_coverage']
        for category, data in sorted(owasp.items()):
            findings = data['findings_count']
            critical = data['critical']
            status = "✅" if findings == 0 else "⚠️"
            print(f"   {status} {category}: {data['title']} ({findings} findings)")
        
        # Module Summary
        print("\n🔧 MODULES EXECUTED:")
        for module, data in report['findings_by_module'].items():
            count = data['findings_count']
            print(f"   ✓ {module}: {count} findings")
        
        print(f"\n{'='*80}\n")


# Usage Example
if __name__ == "__main__":
    target = "example.com"
    
    # Create scanner
    scanner = MasterSecurityScanner(target)
    
    # Execute full scan
    report = scanner.execute_full_scan()
    
    # Print summary
    scanner.print_summary()
    
    # Export report
    scanner.export_json_report(f"security_report_{target}.json")
