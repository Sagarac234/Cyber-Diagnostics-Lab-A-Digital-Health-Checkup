"""
Main Web Security Scanner Orchestrator
Coordinates all security modules and generates unified reports
"""

import time
import sys
import os
# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.web_app_risk import WebAppRiskModule
from modules.security_config import SecurityConfigModule
from modules.owasp_coverage_analyzer import OWASPCoverageAnalyzer
import concurrent.futures


class WebSecurityScanner:
    """
    Main scanner orchestrator - runs all security checks
    """
    
    def __init__(self, target, rules=None):
        self.target = target
        self.rules = rules or {}
        self.results = {}
        self.total_findings = []
        self.start_time = None
        self.end_time = None
    
    def scan(self):
        """Execute comprehensive security scan."""
        self.start_time = time.time()
        
        print(f"\n{'='*60}")
        print(f"🔍 Web Security Scanner - Starting Scan")
        print(f"{'='*60}")
        print(f"Target: {self.target}")
        print(f"Start Time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*60}\n")
        
        # Run modules in parallel for speed
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            futures = {
                executor.submit(self._run_web_app_risk): 'Web App Risk',
                executor.submit(self._run_security_config): 'Security Config',
                executor.submit(self._run_owasp_analysis): 'OWASP Coverage'
            }
            
            for future in concurrent.futures.as_completed(futures):
                module_name = futures[future]
                try:
                    result = future.result()
                    self.results[module_name] = result
                    print(f"✅ {module_name} completed")
                except Exception as e:
                    print(f"❌ {module_name} failed: {str(e)}")
        
        self.end_time = time.time()
        
        # Consolidate all findings
        self._consolidate_findings()
        
        # Generate reports
        return self._generate_final_report()
    
    def _run_web_app_risk(self):
        """Run web app risk module."""
        module = WebAppRiskModule(self.target, self.rules)
        return module.execute()
    
    def _run_security_config(self):
        """Run security configuration module."""
        module = SecurityConfigModule(self.target, self.rules)
        return module.execute()
    
    def _run_owasp_analysis(self):
        """Run OWASP coverage analyzer."""
        module = OWASPCoverageAnalyzer(self.target, self.rules)
        return module.execute()
    
    def _consolidate_findings(self):
        """Consolidate findings from all modules."""
        for module_name, result in self.results.items():
            if 'findings' in result:
                self.total_findings.extend(result['findings'])
    
    def _generate_final_report(self):
        """Generate comprehensive final report."""
        # Categorize findings by severity
        critical = [f for f in self.total_findings if f.get('severity') == 'critical']
        high = [f for f in self.total_findings if f.get('severity') == 'high']
        medium = [f for f in self.total_findings if f.get('severity') == 'medium']
        low = [f for f in self.total_findings if f.get('severity') == 'low']
        info = [f for f in self.total_findings if f.get('severity') == 'info']
        
        duration = self.end_time - self.start_time
        
        report = {
            "scan_summary": {
                "target": self.target,
                "scan_duration": f"{duration:.2f} seconds",
                "total_findings": len(self.total_findings),
                "critical": len(critical),
                "high": len(high),
                "medium": len(medium),
                "low": len(low),
                "info": len(info),
                "risk_score": self._calculate_risk_score(critical, high, medium)
            },
            "findings_by_severity": {
                "critical": critical,
                "high": high,
                "medium": medium,
                "low": low,
                "info": info
            },
            "modules": self.results,
            "recommendations": self._generate_recommendations(critical, high)
        }
        
        return report
    
    def _calculate_risk_score(self, critical, high, medium):
        """Calculate overall risk score (0-100)."""
        score = (len(critical) * 10) + (len(high) * 5) + (len(medium) * 2)
        return min(score, 100)
    
    def _generate_recommendations(self, critical, high):
        """Generate prioritized remediation recommendations."""
        recommendations = []
        
        if critical:
            recommendations.append({
                "priority": "CRITICAL",
                "action": "Address all critical findings immediately",
                "items": len(critical)
            })
        
        if high:
            recommendations.append({
                "priority": "HIGH",
                "action": "Address high severity findings within 24 hours",
                "items": len(high)
            })
        
        return recommendations
