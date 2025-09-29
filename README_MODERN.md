# Modern pefile 2024.1.0

A modernized Python library for parsing Portable Executable (PE) files with Python 3.8+ features.

## 🚀 What's New in 2024.1.0

### Modern Python Features
- **Python 3.8+ only** - No more legacy compatibility code
- **Type hints** - Full type annotation support
- **Dataclasses** - Modern configuration system
- **Context managers** - Automatic resource cleanup
- **Async/await** - Asynchronous file operations
- **pathlib** - Modern path handling

### Security Enhancements
- **File size limits** - Configurable safety limits
- **Input validation** - Type and size checking
- **Security exceptions** - Specific error types
- **Memory safety** - Better resource management

### Developer Experience
- **Modern CLI** - argparse-based command interface
- **Configuration** - Flexible settings via dataclasses
- **Better errors** - Hierarchical exception types
- **Pre-commit hooks** - Code quality automation

## 📦 Installation

```bash
# Install from PyPI (when available)
pip install pefile

# Development installation
pip install -e .[dev]
```

## 🔧 Usage Examples

### Basic Usage (Compatible with old code)
```python
import pefile

# Traditional usage still works
pe = pefile.PE("malware.exe") 
print(pe.dump_info())
```

### Modern Usage with Context Managers
```python
import pefile
from pathlib import Path

# Modern pathlib and context manager support
with pefile.PE(Path("malware.exe")) as pe:
    print(f"Entry point: {hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)}")
    print(f"Sections: {len(pe.sections)}")
```

### Async File Processing
```python
import asyncio
import pefile

async def analyze_file(filepath):
    # Async file loading (requires aiofiles)
    pe = await pefile.PE.from_file_async(filepath)
    return pe.dump_info()

# Process multiple files concurrently
async def main():
    files = ["file1.exe", "file2.dll", "file3.sys"]
    results = await asyncio.gather(*[analyze_file(f) for f in files])
    return results
```

### Custom Configuration  
```python
import pefile

# Custom security settings
config = pefile.PEConfig(
    max_file_size=50 * 1024 * 1024,  # 50MB limit
    enable_security_checks=True,
    strict_parsing=False
)

# Use custom config (future enhancement)
pe = pefile.PE("file.exe")  # Uses DEFAULT_CONFIG
```

### Modern CLI
```bash
# Modern command-line interface
python -m pefile --help
python -m pefile --version
python -m pefile malware.exe
python -m pefile --exports malware.exe
```

## 🛡️ Security Features

### Input Validation
```python
try:
    # File too large
    pe = pefile.PE("huge_file.exe")
except pefile.PESecurityError as e:
    print(f"Security check failed: {e}")

try:
    # Invalid data type
    pe = pefile.PE(data="not bytes")
except pefile.PESecurityError as e:
    print(f"Invalid input: {e}")
```

### Exception Hierarchy
```python
# Specific exception types
try:
    pe = pefile.PE("corrupted.exe")
except pefile.PEImportError:
    print("Import table parsing failed")
except pefile.PEResourceError:
    print("Resource parsing failed")  
except pefile.PESecurityError:
    print("Security validation failed")
except pefile.PEFormatError:
    print("General PE format error")
```

## ⚙️ Configuration

```python
import pefile

# View current configuration
config = pefile.DEFAULT_CONFIG
print(f"Max file size: {config.max_file_size}")
print(f"Security enabled: {config.enable_security_checks}")

# Create custom configuration
custom_config = pefile.PEConfig(
    max_file_size=100 * 1024 * 1024,
    max_sections=1000,
    enable_security_checks=True
)
```

## 🏗️ Development

### Setup Development Environment
```bash
# Clone repository
git clone https://github.com/yji0728/pefile.git
cd pefile

# Install development dependencies
pip install -r requirements-dev.txt

# Install pre-commit hooks
pre-commit install
```

### Code Quality Tools
```bash
# Format code
black .
isort .

# Lint code
flake8 .
mypy pefile.py peutils.py

# Run tests
pytest tests/

# Security scan
bandit -r .
safety check
```

## 📚 API Reference

### Core Classes

#### `PE`
Main class for parsing PE files.

**Parameters:**
- `name: Optional[Union[str, Path]]` - File path to PE file
- `data: Optional[bytes]` - Raw PE data
- `fast_load: Optional[bool]` - Skip detailed parsing
- `max_symbol_exports: int` - Limit for exported symbols
- `max_repeated_symbol: int` - Limit for repeated symbols

**Methods:**
- `close() -> None` - Close file and cleanup resources
- `__enter__() -> PE` - Context manager entry
- `__exit__() -> False` - Context manager exit
- `from_file_async(filepath) -> PE` - Async file loading

#### `PEConfig` 
Configuration dataclass for PE parser settings.

**Attributes:**
- `max_file_size: int` - Maximum file size (default: 100MB)
- `enable_security_checks: bool` - Enable security validation
- `strict_parsing: bool` - Strict parsing mode
- `max_sections: int` - Maximum sections to parse
- `max_import_symbols: int` - Maximum import symbols

### Exception Types

#### `PEFormatError`
Base exception for PE format errors.

#### `PESecurityError` 
Security validation failures.

#### `PEImportError`
Import table parsing errors.

#### `PEResourceError`
Resource parsing errors.

## 🔄 Migration Guide

### From Legacy pefile
The new version maintains full backward compatibility:

```python
# Old code continues to work
import pefile
pe = pefile.PE("file.exe")
print(pe.dump_info())

# But you can now use modern features
with pefile.PE(Path("file.exe")) as pe:
    # Modern context manager
    info = pe.dump_info()
```

### New Features to Adopt
1. **Use context managers** for automatic cleanup
2. **Use pathlib.Path** instead of strings
3. **Handle specific exceptions** instead of generic ones
4. **Use async loading** for better performance
5. **Configure security settings** as needed

## 📄 License

This project maintains the same license as the original pefile.

## 🤝 Contributing

Contributions are welcome! Please ensure:

1. Code follows black formatting
2. Type hints are included
3. Tests are added for new features
4. Security implications are considered
5. Backward compatibility is maintained

## 📝 Changelog

### 2024.1.0
- ✨ Modern Python 3.8+ features
- 🛡️ Enhanced security validation
- 🔧 Context manager support
- ⚙️ Dataclass configuration
- 🚀 Async/await support
- 📦 Modern packaging (pyproject.toml)
- 🧹 Code quality improvements
- 📚 Enhanced documentation