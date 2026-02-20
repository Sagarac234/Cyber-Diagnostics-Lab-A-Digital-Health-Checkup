import json
from datetime import datetime
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.identity_infra import IdentityInfraModule
from modules.security_config import SecurityConfigModule
from modules.threat_intel import ThreatIntelModule
from modules.web_app_risk import WebAppRiskModule
from modules.behavioral import BehavioralModule
from modules.tech_detection import TechDetectionModule


class ScanOrchestrator:
    """
    Orchestrates the execution of security modules and aggregates results.
    """
    
    def __init__(self, target, selected_modules, selected_rules):
        self.target = target
        self.selected_modules = selected_modules  # comma-separated string
        self.selected_rules = selected_rules      # comma-separated string
        self.results = {}
        self.start_time = datetime.now()
        
    def run_scan(self, progress_callback=None):
        """Execute all selected modules and collect results."""
        modules_to_run = self.selected_modules.split(",") if self.selected_modules else []
        
        # Map module keys to module classes
        module_map = {
            "identity_infra": IdentityInfraModule,
            "security_config": SecurityConfigModule,
            "threat_intel": ThreatIntelModule,
            "web_app_risk": WebAppRiskModule,
            "behavioral": BehavioralModule,
        }
        
        # Filter to only valid modules
        modules_to_run = [m.strip() for m in modules_to_run if m.strip() in module_map]
        total_modules = len(modules_to_run)
        
        # Progress constants
        TECH_DETECTION_START = 0
        TECH_DETECTION_END = 5
        MODULES_START = 5
        MODULES_END = 95
        FINALIZING_START = 95
        FINALIZING_END = 100

        # Run Technology Detection (Always)
        if progress_callback:
            progress_callback(TECH_DETECTION_START, "Detecting Tech Stack")
            
        try:
            tech_module = TechDetectionModule()
            self.results['tech_stack'] = tech_module.run(self.target)
        except Exception as e:
            print(f"Tech detection error: {e}")
            self.results['tech_stack'] = {"error": str(e), "technologies": []}

        if progress_callback:
            progress_callback(TECH_DETECTION_END, "Tech Stack Detected")

        # Execute each selected module
        module_range_size = (MODULES_END - MODULES_START) / total_modules if total_modules > 0 else 0
        
        for index, module_key in enumerate(modules_to_run):
            start_pct = MODULES_START + (index * module_range_size)
            end_pct = MODULES_START + ((index + 1) * module_range_size)
            
            def make_sub_callback(m_key, s_pct, e_pct):
                def sub_callback(module_internal_pct, status_msg=None):
                    if progress_callback:
                        overall_pct = int(s_pct + (module_internal_pct / 100.0) * (e_pct - s_pct))
                        msg = f"{m_key}: {status_msg}" if status_msg else m_key
                        progress_callback(overall_pct, msg)
                return sub_callback

            sub_cb = make_sub_callback(module_key, start_pct, end_pct)
            
            # Initial module progress
            sub_cb(0, "Starting...")
            
            try:
                module_class = module_map[module_key]
                # Pass the sub-callback to the module
                module = module_class(self.target, self.selected_rules)
                
                # Check if execute accepts progress_callback
                import inspect
                sig = inspect.signature(module.execute)
                if 'progress_callback' in sig.parameters:
                    self.results[module_key] = module.execute(progress_callback=sub_cb)
                else:
                    self.results[module_key] = module.execute()
                
            except Exception as e:
                print(f"Error in module {module_key}: {e}")
                self.results[module_key] = {
                    "status": "error",
                    "error": str(e),
                    "findings": []
                }
            
            # Ensure module reaches its end percentage
            sub_cb(100, "Completed")
        
        # Final progress update
        if progress_callback:
            progress_callback(FINALIZING_START, "Finalizing results...")
            
        # Add scan metadata
        self.results["metadata"] = {
            "target": self.target,
            "scan_time": self.start_time.isoformat(),
            "duration_seconds": (datetime.now() - self.start_time).total_seconds(),
            "modules_executed": list(self.results.keys()),
            "total_findings": sum(len(r.get("findings", [])) if isinstance(r, dict) else 0 for r in self.results.values())
        }
        
        if progress_callback:
            progress_callback(FINALIZING_END, "Scan Complete")
            
        return self.results
        
        return self.results
    
    def get_findings_by_severity(self):
        """Organize all findings by severity level."""
        findings_by_severity = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": [],
            "info": []
        }
        
        for module_key, module_result in self.results.items():
            if module_key == "metadata":
                continue
            
            for finding in module_result.get("findings", []):
                severity = finding.get("severity", "info").lower()
                if severity in findings_by_severity:
                    findings_by_severity[severity].append({
                        "module": module_key,
                        **finding
                    })
        
        return findings_by_severity
