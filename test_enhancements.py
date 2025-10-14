#!/usr/bin/env python3
"""Test script to demonstrate enhanced PE analyzer functionality."""

import sys
sys.path.insert(0, '.')

import peutils


def test_is_valid():
    """Test is_valid function with mock PE objects."""
    print("Testing is_valid()...")
    
    # Valid PE structure
    class ValidPE:
        class DOS_HEADER:
            e_magic = 0x5A4D  # MZ
        
        class NT_HEADERS:
            Signature = 0x4550  # PE\0\0
        
        class FILE_HEADER:
            Machine = 0x14c  # IMAGE_FILE_MACHINE_I386
            
        class OPTIONAL_HEADER:
            SectionAlignment = 4096
            FileAlignment = 512
        
        class MockSection:
            Misc_VirtualSize = 1000
            VirtualAddress = 0x1000
            SizeOfRawData = 1000
            PointerToRawData = 512
            Name = b'.text\x00\x00\x00'
                
        sections = [MockSection()]
        __data__ = b'MZ' + b'\x00' * 1000
        
        def get_warnings(self):
            return []
    
    valid_pe = ValidPE()
    result = peutils.is_valid(valid_pe)
    assert result == True, "Expected valid PE to pass validation"
    print(f"  ✓ Valid PE detected correctly: {result}")
    
    # Invalid PE structure (missing DOS header)
    class InvalidPE:
        pass
    
    invalid_pe = InvalidPE()
    result = peutils.is_valid(invalid_pe)
    assert result == False, "Expected invalid PE to fail validation"
    print(f"  ✓ Invalid PE detected correctly: {result}")


def test_is_suspicious():
    """Test is_suspicious function with mock PE objects."""
    print("\nTesting is_suspicious()...")
    
    # Normal PE
    class NormalPE:
        class DOS_HEADER:
            e_magic = 0x5A4D
        
        class NT_HEADERS:
            Signature = 0x4550
        
        class FILE_HEADER:
            Machine = 0x14c
            
        class OPTIONAL_HEADER:
            SectionAlignment = 4096
            FileAlignment = 512
            AddressOfEntryPoint = 0x1000
        
        class MockSection:
            def __init__(self, name, va):
                self.Name = name
                self.VirtualAddress = va
                self.Misc_VirtualSize = 1000
                self.SizeOfRawData = 1000
                self.PointerToRawData = 512
                self.Characteristics = 0x60000020
                
            def get_entropy(self):
                return 5.0
        
        sections = [
            MockSection(b'.text\x00\x00\x00', 0x1000),
            MockSection(b'.data\x00\x00\x00', 0x2000),
        ]
        __data__ = b'MZ' + b'\x00' * 1000
        
        class MockImport:
            imports = [object() for _ in range(20)]
        
        DIRECTORY_ENTRY_IMPORT = [MockImport()]
        
        def get_warnings(self):
            return []
    
    normal_pe = NormalPE()
    result = peutils.is_suspicious(normal_pe)
    assert result == False, "Expected normal PE to not be suspicious"
    print(f"  ✓ Normal PE not flagged as suspicious: {result}")
    
    # Suspicious PE with high entropy
    class SuspiciousPE(NormalPE):
        class MockSection:
            def __init__(self, name, va):
                self.Name = name
                self.VirtualAddress = va
                self.Misc_VirtualSize = 1000
                self.SizeOfRawData = 1000
                self.PointerToRawData = 512
                self.Characteristics = 0x60000020
                
            def get_entropy(self):
                return 7.9  # Very high entropy
        
        sections = [MockSection(b'.text\x00\x00\x00', 0x1000)]
    
    suspicious_pe = SuspiciousPE()
    result = peutils.is_suspicious(suspicious_pe)
    assert result == True, "Expected high-entropy PE to be suspicious"
    print(f"  ✓ Suspicious PE detected correctly: {result}")


def test_is_probably_packed():
    """Test is_probably_packed function with mock PE objects."""
    print("\nTesting is_probably_packed()...")
    
    # Normal PE with low entropy
    class NormalPE:
        class MockSection:
            def __init__(self, entropy):
                self._entropy = entropy
                self.SizeOfRawData = 1000
                
            def get_entropy(self):
                return self._entropy
                
            def get_data(self):
                return b'\x00' * self.SizeOfRawData
        
        sections = [
            MockSection(5.0),  # Normal entropy
            MockSection(4.5),  # Normal entropy
        ]
        
        def trim(self):
            return b'\x00' * 5000
    
    normal_pe = NormalPE()
    result = peutils.is_probably_packed(normal_pe)
    assert result == False, "Expected normal PE to not be flagged as packed"
    print(f"  ✓ Normal PE not flagged as packed: {result}")
    
    # Packed PE with high entropy
    class PackedPE:
        class MockSection:
            def __init__(self, entropy, size):
                self._entropy = entropy
                self.SizeOfRawData = size
                
            def get_entropy(self):
                return self._entropy
                
            def get_data(self):
                return b'\x00' * self.SizeOfRawData
        
        sections = [
            MockSection(7.8, 3000),  # High entropy, large section
        ]
        
        def trim(self):
            return b'\x00' * 5000
    
    packed_pe = PackedPE()
    result = peutils.is_probably_packed(packed_pe)
    assert result == True, "Expected high-entropy PE to be flagged as packed"
    print(f"  ✓ Packed PE detected correctly: {result}")


def main():
    """Run all enhancement tests."""
    print("="*60)
    print("PE Analyzer Enhancement Tests")
    print("="*60)
    
    try:
        test_is_valid()
        test_is_suspicious()
        test_is_probably_packed()
        
        print("\n" + "="*60)
        print("✅ All enhancement tests passed!")
        print("="*60)
        return 0
    except AssertionError as e:
        print(f"\n❌ Test failed: {e}")
        return 1
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())
