"""
Groq PoC Generator Plugin for PySpector
Generates Proof of Concept exploits using Groq's AI API

Installation:
    1. Save this file as aipocgen.py
    2. Install: pyspector plugin install aipocgen.py --trust
    3. Configure: Create a config with your Groq API key
    4. Use: pyspector scan /path --plugin aipocgen --plugin-config config.json

Config format (config.json):
{
    "aipocgen": {
        "api_key": "your-groq-api-key-here",
        "model": "llama-3.3-70b",
        "severity_filter": ["HIGH", "CRITICAL"],
        "max_pocs": 5,
        "output_dir": "pocs",
        "dry_run": false
    }
}

Or set environment variable: GROQ_API_KEY=your-key-here
Set "dry_run" to true to generate placeholder PoCs without calling Groq.
"""

import os
import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from dataclasses import dataclass

# This import will work when the plugin is loaded by PySpector
try:
    from pyspector.plugin_system import PySpectorPlugin, PluginMetadata
except ImportError:
    # Fallback for standalone testing
    from plugin_system import PySpectorPlugin, PluginMetadata

# Groq import - optional at import time, enforced during initialization
try:
    from groq import Groq  # type: ignore
except ImportError:  # pragma: no cover - handled at runtime
    Groq = None  # type: ignore


@dataclass
class Vulnerability:
    """Represents a vulnerability finding"""
    vuln_type: str
    file_path: str
    line_number: int
    code_snippet: str
    severity: str
    description: str


class GroqPoCGeneratorPlugin(PySpectorPlugin):
    """
    Plugin that generates Proof of Concept exploits using Groq AI.
    Analyzes PySpector findings and creates safe, educational PoC code.
    """
    
    MODELS = {
        'llama-3.1-70b': 'llama-3.1-70b-versatile',
        'llama-3.1-8b': 'llama-3.1-8b-instant',
        'mixtral-8x7b': 'mixtral-8x7b-32768',
        'llama-3.3-70b': 'llama-3.3-70b-versatile',
    }
    
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="aipocgen",
            version="1.0.0",
            author="Tommaso Bona",
            description="Generate Proof of Concept exploits/PoCs, directly based on PySpector's scan findings, using Groq AI",
            requires=["groq"],
            category="security"
        )
    
    def initialize(self, config: Dict[str, Any]) -> bool:
        """Initialize the plugin with configuration"""
        self.config = dict(config)
        self.dry_run = bool(config.get('dry_run', False))
        self.api_key = config.get('api_key') or os.environ.get('GROQ_API_KEY')
        self.model = config.get('model', 'llama-3.3-70b')
        self.model_id = self.MODELS.get(self.model, self.MODELS['llama-3.3-70b'])
        severity_source = config.get('severity_filter', ['HIGH', 'CRITICAL'])
        self.severity_filter = [str(sev).upper() for sev in severity_source]
        self.max_pocs = int(config.get('max_pocs', 5))
        self.output_dir = config.get('output_dir', 'pocs')
        self.client = None

        if self.dry_run:
            print("[+] Groq PoC Generator initialized (offline mode)")
            print("    Groq API calls are disabled; generating scaffolds only.")
            print(f"    Severity filter: {', '.join(self.severity_filter)}")
            print(f"    Max PoCs: {self.max_pocs}")
            return True

        if Groq is None:
            print("[!] Error: 'groq' package not installed")
            print("[*] Install with: pip install groq")
            print("[*] Set 'dry_run': true in config to run without Groq access")
            return False

        if not self.api_key:
            print("[!] Error: Groq API key not provided")
            print("[*] Set GROQ_API_KEY environment variable or provide in config")
            print("[*] Get a free API key at: https://console.groq.com/keys")
            return False

        try:
            self.client = Groq(api_key=self.api_key)
        except Exception as e:
            print(f"[!] Error initializing Groq client: {e}")
            return False

        print(f"[+] Groq PoC Generator initialized (model: {self.model})")
        print(f"    Severity filter: {', '.join(self.severity_filter)}")
        print(f"    Max PoCs: {self.max_pocs}")

        return True
    
    def validate_config(self, config: Dict[str, Any]) -> tuple[bool, str]:
        """Validate plugin configuration"""
        model = config.get('model', 'llama-3.3-70b')
        if model not in self.MODELS:
            return False, f"Invalid model: {model}. Choose from: {', '.join(self.MODELS.keys())}"

        dry_run = config.get('dry_run', False)
        if not isinstance(dry_run, bool):
            return False, "dry_run must be a boolean value"

        severity_filter = config.get('severity_filter', ['HIGH', 'CRITICAL'])
        if not isinstance(severity_filter, list) or not severity_filter:
            return False, "severity_filter must be a non-empty list of severities"

        valid_severities = {'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'}
        for sev in severity_filter:
            if str(sev).upper() not in valid_severities:
                return False, f"Invalid severity: {sev}. Choose from: {', '.join(sorted(valid_severities))}"

        max_pocs = config.get('max_pocs', 5)
        if not isinstance(max_pocs, int) or max_pocs < 1:
            return False, "max_pocs must be a positive integer"

        output_dir = config.get('output_dir', 'pocs')
        if not isinstance(output_dir, str) or not output_dir.strip():
            return False, "output_dir must be a non-empty string"

        if not dry_run and not config.get('api_key') and not os.environ.get('GROQ_API_KEY'):
            return False, "Provide api_key in config or set GROQ_API_KEY environment variable (or enable dry_run)"

        return True, ""
    
    def process_findings(
        self,
        findings: List[Dict[str, Any]],
        scan_path: Path,
        **kwargs
    ) -> Dict[str, Any]:
        """Process findings and generate PoCs"""
        print(f"\n{'='*60}")
        print("Groq PoC Generator")
        print(f"{'='*60}")
        if self.dry_run:
            print("[*] Offline mode enabled; generating PoC scaffolds without Groq API access.")
        
        # Filter by severity
        filtered = [
            f for f in findings
            if f.get('severity', '').upper() in self.severity_filter
        ]
        
        if not filtered:
            return {
                'success': True,
                'message': f"No findings match severity filter: {', '.join(self.severity_filter)}",
                'data': {'pocs_generated': 0}
            }
        
        print(f"[*] Found {len(filtered)} vulnerabilities matching criteria")
        print(f"[*] Generating up to {self.max_pocs} PoCs...\n")
        
        # Generate PoCs
        pocs = {}
        output_files = []
        
        for i, finding in enumerate(filtered[:self.max_pocs]):
            vuln = Vulnerability(
                vuln_type=finding.get('rule_id', 'Unknown'),
                file_path=finding.get('file', 'Unknown'),
                line_number=finding.get('line', 0),
                code_snippet=finding.get('code', ''),
                severity=finding.get('severity', 'UNKNOWN').upper(),
                description=finding.get('description', '')
            )
            
            print(f"{'='*60}")
            print(f"[*] Generating PoC {i+1}/{min(self.max_pocs, len(filtered))}")
            print(f"[*] Vulnerability: {vuln.vuln_type}")
            print(f"[*] Location: {vuln.file_path}:{vuln.line_number}")
            print(f"[*] Severity: {vuln.severity}")
            print(f"{'='*60}")
            
            poc_code = self._generate_poc(vuln)
            
            if poc_code:
                # Save PoC
                poc_filename = self._create_filename(vuln)
                poc_path = self._save_poc(poc_code, poc_filename, scan_path, vuln)
                
                if poc_path:
                    output_files.append(str(poc_path))
                    pocs[poc_filename] = {
                        'vulnerability': {
                            'type': vuln.vuln_type,
                            'file': vuln.file_path,
                            'line': vuln.line_number,
                            'severity': vuln.severity
                        },
                        'poc_path': str(poc_path)
                    }
                    print(f"[+] PoC saved: {poc_path}")
            else:
                print(f"[!] Failed to generate PoC for {vuln.vuln_type}")
            
            print()
        
        # Save summary
        summary_path = self._save_summary(pocs, scan_path)
        if summary_path:
            output_files.append(str(summary_path))
        
        return {
            'success': True,
            'message': f"Generated {len(pocs)} PoCs",
            'data': {
                'pocs_generated': len(pocs),
                'output_directory': str(Path(scan_path) / self.output_dir)
            },
            'output_files': output_files
        }
    
    def _generate_poc(self, vuln: Vulnerability) -> Optional[str]:
        """Generate PoC using Groq API"""
        if self.dry_run:
            return self._generate_offline_poc(vuln)

        if not self.client:
            print("[!] Groq client is not initialized")
            return None

        system_prompt = """You are an expert security researcher specializing in Python security product vulnerabilities (especially in OSS). Generate safe Proof of Concept code, that's not simulated and can actually be run locally to undeniably verify the potential vulnerability.

CRITICAL RULES:
1. Generate ONLY safe, non-malicious PoC code (i.e. creating a local file as undeniable proof of concept is acceptable; causing harm to systems or data is NOT)
2. Include clear comments explaining the vulnerability
3. Add mitigation recommendations as comments at the end
4. Use only standard Python libraries when possible
5. Keep the PoC under 100 lines, unless absolutely necessary
6. Do NOT include any text outside of the code block in your response
"""

        user_prompt = f"""Generate a Proof of Concept for this vulnerability:

**Vulnerability Details:**
- Type: {vuln.vuln_type}
- Severity: {vuln.severity}
- File: {vuln.file_path}
- Line: {vuln.line_number}
- Description: {vuln.description}

**Vulnerable Code:**
```python
{vuln.code_snippet}
```

**Requirements:**
1. Generate ONLY safe, non-malicious PoC code (i.e. creating a local file as undeniable proof of concept is acceptable; causing harm to systems or data is NOT)
2. Include comments explaining how it works and why it's dangerous
3. Add a MITIGATION section with fixes
4. Make it always locally runnable
5. Keep the PoC under 100 lines, unless absolutely necessary
6. Do NOT include any text outside of the code block in your response

**Output Format:**
Provide ONLY Python code with comments. Start with:

```python
#!/usr/bin/env python3
\"\"\"
PoC for {vuln.vuln_type}
Generated by PySpector Groq Plugin
\"\"\"

# VULNERABILITY EXPLANATION:
# [Explanation]

# EXPLOITATION:
# [How to exploit]

# [full non-simulated PoC code]

# MITIGATION:
# [How to fix]
```"""

        try:
            response = self.client.chat.completions.create(
                model=self.model_id,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=0.3,
                max_tokens=4096,
                top_p=0.9,
            )
            
            content = response.choices[0].message.content
            
            if content:
                # Extract code from markdown if present
                return self._extract_code(content)
            
            return None
            
        except Exception as e:
            print(f"[!] Error calling Groq API: {e}")
            return None
    
    def _generate_offline_poc(self, vuln: Vulnerability) -> str:
        """Generate an offline PoC scaffold when Groq access is unavailable"""
        snippet = (vuln.code_snippet or "").strip()
        snippet_repr = repr(snippet or "# Code snippet unavailable")
        
        lines = [
            "#!/usr/bin/env python3",
            '"""',
            f"PoC scaffold for {vuln.vuln_type}",
            "Generated by PySpector Groq Plugin (offline mode)",
            '"""',
            "",
            f"# Detected file: {vuln.file_path}",
            f"# Detected line: {vuln.line_number}",
            f"# Severity: {vuln.severity}",
            "",
            "def explain():",
            '    """Describe the vulnerability context."""',
            "    return (",
            f"        \"PySpector flagged {vuln.vuln_type} in {vuln.file_path}:{vuln.line_number}. \"",
            "        \"Use this scaffold and consult mitigation guidance once Groq access is available.\"",
            "    )",
            "",
            "def main():",
            "    print(explain())",
            "    print('\\n--- Vulnerable snippet ---')",
            f"    print({snippet_repr})",
            "    print('\\nMITIGATION: Replace this scaffold with a Groq-generated PoC when ready.')",
            "",
            "if __name__ == '__main__':",
            "    main()",
            "",
        ]
        
        return '\n'.join(lines)
    
    def _extract_code(self, response: str) -> str:
        """Extract Python code from response"""
        if '```python' in response:
            parts = response.split('```python')
            if len(parts) > 1:
                code = parts[1].split('```')[0]
                return code.strip()
        elif '```' in response:
            parts = response.split('```')
            if len(parts) > 1:
                return parts[1].strip()
        
        return response.strip()
    
    def _create_filename(self, vuln: Vulnerability) -> str:
        """Create a safe filename for the PoC"""
        safe_type = vuln.vuln_type.replace('/', '_').replace('\\', '_')
        safe_file = Path(vuln.file_path).stem.replace('.', '_')
        return f"{safe_type}_{safe_file}_line{vuln.line_number}.py"
    
    def _save_poc(
        self,
        poc_code: str,
        filename: str,
        scan_path: Path,
        vuln: Vulnerability
    ) -> Optional[Path]:
        """Save PoC to file"""
        try:
            base_path = Path(scan_path)
            if base_path.is_file():
                base_path = base_path.parent

            output_dir = base_path / self.output_dir
            output_dir.mkdir(parents=True, exist_ok=True)
            
            poc_path = output_dir / filename
            
            with open(poc_path, 'w', encoding='utf-8') as f:
                f.write(poc_code)
            
            return poc_path
            
        except Exception as e:
            print(f"[!] Error saving PoC: {e}")
            return None
    
    def _save_summary(self, pocs: Dict, scan_path: Path) -> Optional[Path]:
        """Save summary JSON"""
        try:
            base_path = Path(scan_path)
            if base_path.is_file():
                base_path = base_path.parent

            output_dir = base_path / self.output_dir
            summary_path = output_dir / "pocs_summary.json"
            
            with open(summary_path, 'w', encoding='utf-8') as f:
                json.dump(pocs, f, indent=2)
            
            print(f"[+] Summary saved: {summary_path}")
            return summary_path
            
        except Exception as e:
            print(f"[!] Error saving summary: {e}")
            return None
    
    def cleanup(self) -> None:
        """Cleanup resources"""
        pass


# This allows the plugin to be tested standalone
if __name__ == "__main__":
    print("Groq PoC Generator Plugin for PySpector")
    print("="*60)
    print(f"Version: {GroqPoCGeneratorPlugin().metadata.version}")
    print(f"Author: {GroqPoCGeneratorPlugin().metadata.author}")
    print(f"Description: {GroqPoCGeneratorPlugin().metadata.description}")
    print("="*60)
    print("\nThis is a PySpector plugin.")
    print("Install with: pyspector plugin install aipogen.py")
