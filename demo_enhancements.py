#!/usr/bin/env python3
"""
Enhanced PE Analyzer Demonstration

This script demonstrates the enhanced PE analysis capabilities.
It shows how to use the new is_valid() and is_suspicious() functions
to analyze PE files for validity and potential security issues.

Usage:
    python3 demo_enhancements.py [PE_FILE]
    
If no PE file is provided, it will demonstrate with mock PE objects.
"""

import sys
import os

# Add current directory to path
sys.path.insert(0, '.')

import pefile
import peutils


def analyze_pe_file(pe_path):
    """Analyze a real PE file."""
    print(f"\n📋 Analyzing: {pe_path}")
    print("=" * 70)
    
    try:
        pe = pefile.PE(pe_path)
        
        # Basic information
        print(f"\n📊 Basic Information:")
        print(f"  Machine Type: {hex(pe.FILE_HEADER.Machine)}")
        print(f"  Number of Sections: {pe.FILE_HEADER.NumberOfSections}")
        print(f"  Entry Point: {hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)}")
        
        # Enhanced analysis
        print(f"\n🔍 Enhanced Analysis:")
        
        is_valid = peutils.is_valid(pe)
        print(f"  Valid PE Structure: {'✅ YES' if is_valid else '❌ NO'}")
        
        is_suspicious = peutils.is_suspicious(pe)
        print(f"  Suspicious Indicators: {'⚠️  YES' if is_suspicious else '✅ NO'}")
        
        is_packed = peutils.is_probably_packed(pe)
        print(f"  Probably Packed: {'⚠️  YES' if is_packed else '✅ NO'}")
        
        # Check if it's a driver
        if hasattr(pe, 'is_driver'):
            is_driver = pe.is_driver()
            print(f"  Windows Driver: {'YES' if is_driver else 'NO'}")
        
        # Section analysis
        print(f"\n📁 Section Analysis:")
        for section in pe.sections:
            section_name = section.Name.rstrip(b'\x00').decode('utf-8', errors='ignore')
            entropy = section.get_entropy()
            print(f"  {section_name:8s}: Entropy={entropy:.2f}, Size={section.SizeOfRawData}")
        
        # Import analysis
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            total_imports = sum(len(entry.imports) for entry in pe.DIRECTORY_ENTRY_IMPORT)
            print(f"\n📦 Imports: {total_imports} total from {len(pe.DIRECTORY_ENTRY_IMPORT)} DLLs")
        
        # Warnings
        warnings = pe.get_warnings()
        if warnings:
            print(f"\n⚠️  Warnings:")
            for warning in warnings[:5]:  # Show first 5
                print(f"  • {warning}")
            if len(warnings) > 5:
                print(f"  ... and {len(warnings) - 5} more")
        
        print("\n" + "=" * 70)
        
    except pefile.PEFormatError as e:
        print(f"❌ Not a valid PE file: {e}")
    except FileNotFoundError:
        print(f"❌ File not found: {pe_path}")
    except Exception as e:
        print(f"❌ Error analyzing file: {e}")
        import traceback
        traceback.print_exc()


def demonstrate_with_mock():
    """Demonstrate functionality with mock PE objects."""
    print("\n🔬 Demonstration with Mock PE Objects")
    print("=" * 70)
    
    # Helper classes for mock PE
    class MockImport:
        def __init__(self, num_imports):
            self.imports = [object() for _ in range(num_imports)]
    
    # Example 1: Normal PE
    print("\n1️⃣  Normal Executable (Clean)")
    print("-" * 70)
    
    class NormalPE:
        class DOS_HEADER:
            e_magic = 0x5A4D
        
        class NT_HEADERS:
            Signature = 0x4550
        
        class FILE_HEADER:
            Machine = 0x14c  # x86
            NumberOfSections = 3
            
        class OPTIONAL_HEADER:
            SectionAlignment = 4096
            FileAlignment = 512
            AddressOfEntryPoint = 0x1000
        
        class MockSection:
            def __init__(self, name, va, size, entropy=5.0):
                self.Name = name
                self.VirtualAddress = va
                self.Misc_VirtualSize = size
                self.SizeOfRawData = size
                self.PointerToRawData = 512 + va
                self.Characteristics = 0x60000020
                self._entropy = entropy
                
            def get_entropy(self):
                return self._entropy
                
            def get_data(self):
                return b'\x00' * self.SizeOfRawData
        
        sections = [
            MockSection(b'.text\x00\x00\x00', 0x1000, 5000, 5.2),
            MockSection(b'.data\x00\x00\x00', 0x3000, 2000, 4.8),
            MockSection(b'.rdata\x00\x00', 0x5000, 1000, 4.5),
        ]
        
        __data__ = b'MZ' + b'\x00' * 10000
        DIRECTORY_ENTRY_IMPORT = [MockImport(25)]
        
        def get_warnings(self):
            return []
            
        def trim(self):
            return self.__data__
    
    normal_pe = NormalPE()
    print(f"  Valid Structure: {'✅' if peutils.is_valid(normal_pe) else '❌'}")
    print(f"  Suspicious: {'⚠️ ' if peutils.is_suspicious(normal_pe) else '✅'}")
    print(f"  Probably Packed: {'⚠️ ' if peutils.is_probably_packed(normal_pe) else '✅'}")
    
    # Example 2: Suspicious PE
    print("\n2️⃣  Suspicious Executable (Potential Malware)")
    print("-" * 70)
    
    class SuspiciousPE(NormalPE):
        class MockSection:
            def __init__(self, name, va, size, entropy=7.9):
                self.Name = name
                self.VirtualAddress = va
                self.Misc_VirtualSize = size
                self.SizeOfRawData = size
                self.PointerToRawData = 512
                self.Characteristics = 0xE0000020  # W+X
                self._entropy = entropy
                
            def get_entropy(self):
                return self._entropy
                
            def get_data(self):
                return b'\x00' * self.SizeOfRawData
        
        sections = [
            MockSection(b'.packed\x00\x00', 0x1000, 8000, 7.9),
        ]
        
        DIRECTORY_ENTRY_IMPORT = [MockImport(2)]  # Very few imports
        
        def get_warnings(self):
            return ["Unusual section characteristics", "High entropy detected"]
    
    suspicious_pe = SuspiciousPE()
    print(f"  Valid Structure: {'✅' if peutils.is_valid(suspicious_pe) else '❌'}")
    print(f"  Suspicious: {'⚠️  YES' if peutils.is_suspicious(suspicious_pe) else '✅ NO'}")
    print(f"  Probably Packed: {'⚠️  YES' if peutils.is_probably_packed(suspicious_pe) else '✅ NO'}")
    print(f"  Indicators: High entropy, W+X sections, few imports")
    
    # Example 3: Invalid PE
    print("\n3️⃣  Invalid PE (Corrupted/Fake)")
    print("-" * 70)
    
    class InvalidPE:
        class DOS_HEADER:
            e_magic = 0x1234  # Wrong magic
    
    invalid_pe = InvalidPE()
    print(f"  Valid Structure: {'✅' if peutils.is_valid(invalid_pe) else '❌ NO'}")
    print(f"  Reason: Invalid DOS header signature")
    
    print("\n" + "=" * 70)


def main():
    """Main entry point."""
    print("\n🚀 Enhanced PE Analyzer")
    print("=" * 70)
    print("This tool demonstrates enhanced PE analysis capabilities including:")
    print("  • Structure validation (is_valid)")
    print("  • Malware detection (is_suspicious)")
    print("  • Packer detection (is_probably_packed)")
    print("=" * 70)
    
    if len(sys.argv) > 1:
        # Analyze provided PE file
        pe_path = sys.argv[1]
        if not os.path.exists(pe_path):
            print(f"\n❌ Error: File not found: {pe_path}")
            return 1
        analyze_pe_file(pe_path)
    else:
        # Demonstrate with mock objects
        demonstrate_with_mock()
        print("\n💡 Tip: Run with a PE file path to analyze a real file:")
        print("   python3 demo_enhancements.py <path_to_pe_file>")
    
    print()
    return 0


if __name__ == '__main__':
    sys.exit(main())
