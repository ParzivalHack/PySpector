"""
PySpector Plugin System
Secure, extensible plugin architecture for PySpector
"""

import ast
import importlib.util
import inspect
import json
import os
import re
import shutil
import sys
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List, Optional, Type
import hashlib


class PluginMetadata:
    """Metadata for a plugin"""
    def __init__(
        self,
        name: str,
        version: str,
        author: str,
        description: str,
        requires: List[str] = None,
        category: str = "general"
    ):
        self.name = name
        self.version = version
        self.author = author
        self.description = description
        self.requires = requires or []
        self.category = category


class PySpectorPlugin(ABC):
    """
    Base class for all PySpector plugins.
    Plugins must inherit from this class and implement required methods.
    """
    
    @property
    @abstractmethod
    def metadata(self) -> PluginMetadata:
        """Return plugin metadata"""
        pass
    
    @abstractmethod
    def initialize(self, config: Dict[str, Any]) -> bool:
        """
        Initialize the plugin with configuration.
        
        Args:
            config: Plugin-specific configuration
            
        Returns:
            True if initialization succeeded, False otherwise
        """
        pass
    
    @abstractmethod
    def process_findings(
        self, 
        findings: List[Dict[str, Any]], 
        scan_path: Path,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Process PySpector findings.
        
        Args:
            findings: List of vulnerability findings from PySpector
            scan_path: Path that was scanned
            **kwargs: Additional arguments passed from CLI
            
        Returns:
            Dictionary with plugin results:
            {
                'success': bool,
                'message': str,
                'data': Any,
                'output_files': List[str]  # Optional: paths to generated files
            }
        """
        pass
    
    def cleanup(self) -> None:
        """
        Cleanup resources before plugin unload.
        Called automatically by the plugin manager.
        """
        pass
    
    def validate_config(self, config: Dict[str, Any]) -> tuple[bool, str]:
        """
        Validate plugin configuration.
        
        Args:
            config: Configuration to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        return True, ""


class PluginSecurity:
    """Security utilities for plugin system"""
    
    DANGEROUS_MODULES = {
        'os.system', 'subprocess.Popen', 'eval', 'exec',
        '__import__', 'compile'
    }
    
    ALLOWED_IMPORTS = {
        'json', 'pathlib', 'typing', 'dataclasses', 're',
        'datetime', 'collections', 'itertools', 'functools'
    }
    
    @staticmethod
    def calculate_checksum(file_path: Path) -> str:
        """Calculate SHA256 checksum of a plugin file"""
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                sha256.update(chunk)
        return sha256.hexdigest()
    
    @staticmethod
    def validate_plugin_code(plugin_path: Path) -> tuple[bool, str]:
        """
        Basic static analysis of plugin code for security.

        Returns:
            Tuple of (is_safe, message)
        """

        fatal_calls = {
            "eval",
            "exec",
            "compile",
            "__import__",
            "os.system",
            "os.popen",
            "subprocess.Popen",
            "subprocess.run",
            "subprocess.call",
            "subprocess.check_call",
            "subprocess.check_output",
        }
        warning_calls = {
            "open",
            "builtins.open",
        }

        try:
            source = plugin_path.read_text()
            tree = ast.parse(source, filename=str(plugin_path))
        except Exception as exc:
            return False, f"Error validating plugin: {exc}"

        alias_map: Dict[str, str] = {}
        detected_fatal: set[str] = set()
        detected_warnings: set[str] = set()

        def register_alias(alias: str, target: str) -> None:
            alias_map[alias] = target

        def resolve_name(node: ast.AST) -> Optional[str]:
            if isinstance(node, ast.Name):
                target = alias_map.get(node.id, node.id)
                return target
            if isinstance(node, ast.Attribute):
                attrs: List[str] = []
                current = node
                while isinstance(current, ast.Attribute):
                    attrs.append(current.attr)
                    current = current.value
                if isinstance(current, ast.Name):
                    base = alias_map.get(current.id, current.id)
                    attrs.append(base)
                    attrs.reverse()
                    return ".".join(attrs)
            return None

        class Analyzer(ast.NodeVisitor):
            def visit_Import(self, node: ast.Import) -> None:
                for alias in node.names:
                    register_alias(alias.asname or alias.name, alias.name)
                self.generic_visit(node)

            def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
                module = node.module or ""
                for alias in node.names:
                    target = f"{module}.{alias.name}" if module else alias.name
                    register_alias(alias.asname or alias.name, target)
                self.generic_visit(node)

            def visit_Call(self, node: ast.Call) -> None:
                name = resolve_name(node.func)
                if name:
                    simplified = name.replace("builtins.", "")

                    # Handle alias that already resolved to dotted path
                    if simplified in fatal_calls:
                        detected_fatal.add(simplified)
                    elif simplified in warning_calls:
                        detected_warnings.add(simplified)
                    else:
                        # Check dotted paths by normalising alias root
                        parts = simplified.split(".")
                        if parts:
                            root = alias_map.get(parts[0], parts[0])
                            normalised = ".".join([root, *parts[1:]]) if len(parts) > 1 else root
                            normalised = normalised.replace("builtins.", "")

                            if normalised in fatal_calls:
                                detected_fatal.add(normalised)
                            elif normalised in warning_calls:
                                detected_warnings.add(normalised)

                self.generic_visit(node)

        Analyzer().visit(tree)

        if detected_fatal:
            ordered = ", ".join(sorted(detected_fatal))
            return False, f"Plugin uses high-risk calls: {ordered}"

        if detected_warnings:
            ordered = ", ".join(sorted(detected_warnings))
            return True, f"Plugin uses sensitive operations: {ordered}"

        return True, ""
    
    @staticmethod
    def verify_checksum(plugin_path: Path, expected_checksum: str) -> bool:
        """Verify plugin file checksum"""
        actual = PluginSecurity.calculate_checksum(plugin_path)
        return actual == expected_checksum


def _resolve_project_root() -> Path:
    """
    Resolve the root of the PySpector project.

    Prefer an explicit override via PYSPECTOR_PLUGIN_ROOT, otherwise try to
    locate the repository root by searching for common project markers. As a
    final fallback use the current working directory.
    """
    override = os.environ.get("PYSPECTOR_PLUGIN_ROOT")
    if override:
        return Path(override).expanduser().resolve()

    markers = (
        "pyproject.toml",
        "setup.cfg",
        ".git",
        "README.md",
        "src",
    )

    def find_root(start: Path) -> Optional[Path]:
        start = start.resolve()
        for candidate in (start, *start.parents):
            if any((candidate / marker).exists() for marker in markers):
                if (candidate / "src" / "pyspector").exists() or (candidate / "plugins").exists():
                    return candidate
                if any((candidate / marker).exists() for marker in ("pyproject.toml", "setup.cfg", ".git")):
                    return candidate
        return None

    module_path = Path(__file__).resolve().parent
    for origin in (Path.cwd(), module_path):
        root = find_root(origin)
        if root:
            return root

    return Path.cwd().resolve()


def _ensure_directory(path: Path) -> Path:
    """Create the directory if it does not already exist and return it."""
    path.mkdir(parents=True, exist_ok=True)
    return path


def _resolve_plugin_directory() -> Path:
    """Return the managed plugin directory inside the project root."""
    project_root = _ensure_directory(_resolve_project_root())
    return _ensure_directory(project_root / "plugins")


def _resolve_registry_path() -> Path:
    """Return the path to the plugin registry file inside the plugin directory."""
    plugin_dir = _ensure_directory(_resolve_plugin_directory())
    return plugin_dir / "plugin_registry.json"


class PluginRegistry:
    """Registry for tracking installed and trusted plugins"""
    
    def __init__(self, registry_path: Path):
        self.registry_path = registry_path
        self.plugins: Dict[str, Dict[str, Any]] = {}
        self._load_registry()
    
    def _load_registry(self):
        """Load plugin registry from disk"""
        if self.registry_path.exists():
            try:
                with open(self.registry_path, 'r') as f:
                    self.plugins = json.load(f)
            except (json.JSONDecodeError, IOError):
                self.plugins = {}
    
    def save_registry(self):
        """Save plugin registry to disk"""
        self.registry_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.registry_path, 'w') as f:
            json.dump(self.plugins, f, indent=2)
    
    def register_plugin(
        self,
        name: str,
        path: str,
        checksum: str,
        metadata: PluginMetadata,
        trusted: bool = False
    ):
        """Register a plugin in the registry"""
        self.plugins[name] = {
            'path': path,
            'checksum': checksum,
            'version': metadata.version,
            'author': metadata.author,
            'category': metadata.category,
            'trusted': trusted,
            'enabled': True
        }
        self.save_registry()
    
    def is_trusted(self, name: str) -> bool:
        """Check if a plugin is trusted"""
        return self.plugins.get(name, {}).get('trusted', False)
    
    def get_plugin_info(self, name: str) -> Optional[Dict[str, Any]]:
        """Get plugin information from registry"""
        return self.plugins.get(name)
    
    def list_plugins(self) -> List[Dict[str, Any]]:
        """List all registered plugins"""
        return [
            {'name': name, **info}
            for name, info in self.plugins.items()
        ]


class PluginManager:
    """Manages plugin loading, validation, and execution"""
    
    def __init__(self, plugin_dir: Path, registry_path: Path):
        self.plugin_dir = plugin_dir
        self.plugin_dir.mkdir(parents=True, exist_ok=True)
        self.registry = PluginRegistry(registry_path)
        self.loaded_plugins: Dict[str, PySpectorPlugin] = {}

    _PLUGIN_NAME_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

    def _normalize_plugin_name(self, plugin_name: str) -> Optional[str]:
        """Normalise user-supplied plugin identifiers to safe module names."""
        candidate = plugin_name.strip().replace("-", "_")
        if not candidate:
            return None
        if not self._PLUGIN_NAME_PATTERN.match(candidate):
            return None
        return candidate

    def _plugin_file_path(self, plugin_name: str) -> Path:
        """Return the on-disk path for a plugin."""
        return self.plugin_dir / f"{plugin_name}.py"

    def _stage_plugin(self, source_path: Path, plugin_name: str, overwrite: bool) -> Optional[Path]:
        """
        Copy a plugin source file into the managed plugins directory.
        Returns the destination path on success.
        """
        try:
            resolved_source = source_path.resolve(strict=True)
        except FileNotFoundError:
            print(f"[!] Plugin source '{source_path}' not found")
            return None

        if not resolved_source.is_file():
            print(f"[!] Plugin source '{resolved_source}' must be a Python file")
            return None

        if resolved_source.suffix.lower() != ".py":
            print(f"[!] Plugin '{resolved_source.name}' must be a '.py' file")
            return None

        destination = self._plugin_file_path(plugin_name)
        destination.parent.mkdir(parents=True, exist_ok=True)

        destination_exists = destination.exists()
        if destination_exists:
            try:
                if os.path.samefile(destination, resolved_source):
                    return destination
            except (FileNotFoundError, OSError):
                pass
            if not overwrite:
                print(f"[!] Plugin '{plugin_name}' already exists at {destination}")
                return None

        temp_destination = destination
        if destination_exists:
            temp_destination = destination.with_suffix(destination.suffix + ".tmp")
            try:
                if temp_destination.exists():
                    temp_destination.unlink()
            except OSError:
                pass

        try:
            shutil.copy2(resolved_source, temp_destination)
            if temp_destination != destination:
                temp_destination.replace(destination)
        except Exception as exc:
            print(f"[!] Failed to copy plugin to '{destination}': {exc}")
            try:
                if temp_destination != destination and temp_destination.exists():
                    temp_destination.unlink()
            except OSError:
                pass
            return None

        return destination

    def install_plugin_file(self, plugin_name: str, source_path: Path, overwrite: bool = False) -> Optional[Path]:
        """
        Install or update a plugin file in the managed directory without trusting it.
        """
        normalised = self._normalize_plugin_name(plugin_name)
        if not normalised:
            print(f"[!] Invalid plugin name '{plugin_name}'. Use letters, numbers, and underscores.")
            return None
        return self._stage_plugin(source_path, normalised, overwrite)
    
    def discover_plugins(self) -> List[Path]:
        """Discover all plugin files in the plugin directory"""
        return list(self.plugin_dir.glob("*.py"))
    
    def load_plugin(
        self,
        plugin_name: str,
        require_trusted: bool = True,
        force_load: bool = False
    ) -> Optional[PySpectorPlugin]:
        """
        Load a plugin by name.
        
        Args:
            plugin_name: Name of the plugin to load
            require_trusted: Only load trusted plugins
            force_load: Force load even if security checks fail
            
        Returns:
            Loaded plugin instance or None
        """
        normalised = self._normalize_plugin_name(plugin_name)
        if not normalised:
            print(f"[!] Invalid plugin name '{plugin_name}'. Plugins must use letters, numbers, or underscores.")
            return None

        # Check if already loaded
        if normalised in self.loaded_plugins:
            return self.loaded_plugins[normalised]

        # Find plugin file
        plugin_path = self._plugin_file_path(normalised)

        if not plugin_path.exists():
            print(f"[!] Plugin '{normalised}' not found at {plugin_path}")
            return None
        
        # Security checks
        plugin_info = self.registry.get_plugin_info(normalised)
        
        if require_trusted and not force_load:
            if not plugin_info or not plugin_info.get('trusted'):
                print(f"[!] Plugin '{normalised}' is not trusted.")
                print(f"[*] Use 'pyspector plugin trust {normalised}' to trust it.")
                
                # Perform security scan
                is_safe, warning = PluginSecurity.validate_plugin_code(plugin_path)
                if not is_safe:
                    print(f"[!] Security warning: {warning}")
                    return None
                if warning:
                    print(f"[*] Security note: {warning}")
                
                # Ask for confirmation
                response = input(f"Do you want to trust and load '{normalised}'? [y/N]: ").strip().lower()
                if response not in ['y', 'yes']:
                    return None
        
        # Verify checksum if plugin is registered
        if plugin_info:
            checksum = PluginSecurity.calculate_checksum(plugin_path)
            if checksum != plugin_info.get('checksum'):
                print(f"[!] WARNING: Plugin '{normalised}' checksum mismatch!")
                print("[!] File may have been modified.")
                if not force_load:
                    response = input("Load anyway? [y/N]: ").strip().lower()
                    if response not in ['y', 'yes']:
                        return None
        
        # Load the plugin module
        try:
            spec = importlib.util.spec_from_file_location(normalised, plugin_path)
            if not spec or not spec.loader:
                raise ImportError(f"Cannot load plugin spec for {normalised}")
            
            module = importlib.util.module_from_spec(spec)
            sys.modules[normalised] = module
            spec.loader.exec_module(module)
            
            # Find plugin class
            plugin_class = self._find_plugin_class(module)
            if not plugin_class:
                print(f"[!] No valid plugin class found in '{normalised}'")
                return None
            
            # Instantiate plugin
            plugin_instance = plugin_class()
            
            # Register if not already registered
            if not plugin_info:
                checksum = PluginSecurity.calculate_checksum(plugin_path)
                self.registry.register_plugin(
                    normalised,
                    str(plugin_path),
                    checksum,
                    plugin_instance.metadata,
                    trusted=force_load
                )
            
            self.loaded_plugins[normalised] = plugin_instance
            
            print(f"[+] Loaded plugin: {plugin_instance.metadata.name} v{plugin_instance.metadata.version}")
            
            return plugin_instance
            
        except Exception as e:
            print(f"[!] Error loading plugin '{normalised}': {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def _find_plugin_class(self, module) -> Optional[Type[PySpectorPlugin]]:
        """Find the plugin class in a module"""
        for name, obj in inspect.getmembers(module, inspect.isclass):
            if (issubclass(obj, PySpectorPlugin) and 
                obj != PySpectorPlugin and
                not inspect.isabstract(obj)):
                return obj
        return None
    
    def execute_plugin(
        self,
        plugin: PySpectorPlugin,
        findings: List[Dict[str, Any]],
        scan_path: Path,
        plugin_config: Dict[str, Any] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Execute a plugin.
        
        Args:
            plugin: Plugin instance to execute
            findings: PySpector findings
            scan_path: Path that was scanned
            plugin_config: Plugin-specific configuration
            **kwargs: Additional arguments
            
        Returns:
            Plugin execution results
        """
        try:
            # Initialize plugin
            config = plugin_config or {}
            
            # Validate config
            is_valid, error_msg = plugin.validate_config(config)
            if not is_valid:
                return {
                    'success': False,
                    'message': f"Invalid plugin configuration: {error_msg}",
                    'data': None
                }
            
            if not plugin.initialize(config):
                return {
                    'success': False,
                    'message': "Plugin initialization failed",
                    'data': None
                }
            
            print(f"[*] Executing plugin: {plugin.metadata.name}")
            
            # Execute plugin
            result = plugin.process_findings(findings, scan_path, **kwargs)
            
            # Cleanup
            plugin.cleanup()
            
            return result
            
        except Exception as e:
            print(f"[!] Plugin execution error: {e}")
            import traceback
            traceback.print_exc()
            
            return {
                'success': False,
                'message': f"Plugin execution failed: {e}",
                'data': None
            }
    
    def unload_plugin(self, plugin_name: str):
        """Unload a plugin"""
        normalised = self._normalize_plugin_name(plugin_name)
        if not normalised or normalised not in self.loaded_plugins:
            return
        plugin = self.loaded_plugins[normalised]
        plugin.cleanup()
        del self.loaded_plugins[normalised]
        if normalised in sys.modules:
            del sys.modules[normalised]
    
    def list_available_plugins(self) -> List[str]:
        """List all available plugins"""
        return [p.stem for p in self.discover_plugins()]
    
    def trust_plugin(self, plugin_name: str, source_path: Optional[Path] = None, overwrite: bool = False) -> bool:
        """Mark a plugin as trusted and ensure it resides in the managed directory."""
        normalised = self._normalize_plugin_name(plugin_name)
        if not normalised:
            print(f"[!] Invalid plugin name '{plugin_name}'. Use letters, numbers, and underscores.")
            return False

        if source_path is not None:
            plugin_path = self._stage_plugin(source_path, normalised, overwrite=overwrite)
            if not plugin_path:
                return False
        else:
            plugin_path = self._plugin_file_path(normalised)
            if not plugin_path.exists():
                print(f"[!] Plugin '{normalised}' not found at {plugin_path}")
                return False
        
        # Validate plugin code
        is_safe, warning = PluginSecurity.validate_plugin_code(plugin_path)
        
        if not is_safe:
            print(f"[!] Security warning: {warning}")
            response = input("Trust this plugin anyway? [y/N]: ").strip().lower()
            if response not in ['y', 'yes']:
                return False
        elif warning:
            print(f"[*] Security note: {warning}")
        
        # Calculate checksum
        checksum = PluginSecurity.calculate_checksum(plugin_path)

        # Try to load to get metadata
        plugin = self.load_plugin(normalised, require_trusted=False, force_load=True)
        if not plugin:
            return False
        
        # Update registry
        self.registry.register_plugin(
            normalised,
            str(plugin_path),
            checksum,
            plugin.metadata,
            trusted=True
        )
        
        print(f"[+] Plugin '{normalised}' is now trusted")
        
        return True


# Example plugin for reference
class ExamplePlugin(PySpectorPlugin):
    """Example plugin implementation"""
    
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="example",
            version="1.0.0",
            author="PySpector Team",
            description="Example plugin for demonstration",
            category="example"
        )
    
    def initialize(self, config: Dict[str, Any]) -> bool:
        self.config = config
        return True
    
    def process_findings(
        self,
        findings: List[Dict[str, Any]],
        scan_path: Path,
        **kwargs
    ) -> Dict[str, Any]:
        return {
            'success': True,
            'message': f"Processed {len(findings)} findings",
            'data': {'count': len(findings)}
        }
    
    def cleanup(self) -> None:
        pass


def get_plugin_manager() -> PluginManager:
    """Get or create the global plugin manager instance"""
    plugin_dir = _resolve_plugin_directory()
    registry_path = _resolve_registry_path()
    return PluginManager(plugin_dir, registry_path)
