from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Dict, List, Set, Tuple, Optional, Pattern, Callable
import re


@dataclass
class InstructionPattern:
    """Represents a pattern for matching architecture-specific instructions."""

    name: str
    pattern: Pattern[str]
    extract_registers: Callable


@dataclass
class TransferRule:
    """Represents a rule for extracting register transfers from instructions."""

    pattern: InstructionPattern
    bidirectional: bool = False  # For instructions like xchg


class Architecture(ABC):
    """Abstract base class for different CPU architectures."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Architecture name (e.g., 'x86', 'x64', 'arm64')."""
        pass

    @property
    @abstractmethod
    def register_sets(self) -> Dict[str, Set[str]]:
        """Dictionary of register sets by bit width (e.g., {'32': set(...), '64': set(...)})."""
        pass

    @property
    @abstractmethod
    def default_mode(self) -> str:
        """Default register mode for this architecture."""
        pass

    @property
    @abstractmethod
    def transfer_rules(self) -> List[TransferRule]:
        """List of transfer rules for detecting register transfers."""
        pass

    @abstractmethod
    def get_registers_for_mode(self, mode: Optional[str] = None) -> Set[str]:
        """Get the set of registers for a specific mode."""
        pass

    @abstractmethod
    def is_register_compatible(self, reg: str, mode: Optional[str] = None) -> bool:
        """Check if a register is compatible with the given mode."""
        pass

    @abstractmethod
    def contains_incompatible_registers(self, instructions: str, mode: Optional[str] = None) -> bool:
        """Check if instructions contain registers incompatible with the mode."""
        pass

    def should_include_registers(self, reg1: str, reg2: str, mode: Optional[str] = None) -> bool:
        """Check if both registers are compatible with the specified mode."""
        if mode is None:
            return True
        return self.is_register_compatible(reg1, mode) and self.is_register_compatible(reg2, mode)

    def extract_transfers(self, gadget, mode: Optional[str] = None, strict_mode: bool = False) -> List[Tuple[str, str]]:
        """Extract register transfers from a gadget's instructions."""
        transfers = []
        instructions = gadget.instructions

        # Skip gadgets with mixed register sizes in strict mode
        if strict_mode:
            incompatible_modes = []
            for mode_name, reg_set in self.register_sets.items():
                if self._contains_registers_from_set(instructions, reg_set):
                    incompatible_modes.append(mode_name)

            if len(incompatible_modes) > 1:
                return transfers

        # Skip gadgets with incompatible registers for the specified mode
        if mode and strict_mode and self.contains_incompatible_registers(instructions, mode):
            return transfers

        # Apply transfer rules
        for rule in self.transfer_rules:
            matches = rule.pattern.pattern.finditer(instructions)
            for match in matches:
                transfer = rule.pattern.extract_registers(match)
                if transfer and self.should_include_registers(transfer[0], transfer[1], mode):
                    transfers.append(transfer)
                    # Add reverse transfer for bidirectional instructions
                    if rule.bidirectional:
                        transfers.append((transfer[1], transfer[0]))

        return transfers

    def _contains_registers_from_set(self, instructions: str, reg_set: Set[str]) -> bool:
        """Check if instructions contain any registers from the given set."""
        for reg in reg_set:
            if re.search(r"\b" + re.escape(reg) + r"\b", instructions):
                return True
        return False


class X86Architecture(Architecture):
    """x86 (32-bit) architecture implementation."""

    def __init__(self):
        self._register_sets = {"32": {"eax", "ebx", "ecx", "edx", "esi", "edi", "esp", "ebp"}}
        self._setup_transfer_rules()

    @property
    def name(self) -> str:
        return "x86"

    @property
    def register_sets(self) -> Dict[str, Set[str]]:
        return self._register_sets

    @property
    def default_mode(self) -> str:
        return "32"

    @property
    def transfer_rules(self) -> List[TransferRule]:
        return self._transfer_rules

    def get_registers_for_mode(self, mode: Optional[str] = None) -> Set[str]:
        if mode is None:
            mode = self.default_mode
        return self._register_sets.get(mode, set())

    def is_register_compatible(self, reg: str, mode: Optional[str] = None) -> bool:
        if mode is None:
            return reg in self._register_sets["32"]
        return reg in self._register_sets.get(mode, set())

    def contains_incompatible_registers(self, instructions: str, mode: Optional[str] = None) -> bool:
        if mode is None or mode == "32":
            return False
        # For x86, any non-32-bit registers would be incompatible
        return False

    def _setup_transfer_rules(self):
        """Setup transfer rules for x86 instructions."""
        # Push/pop pattern
        push_pop_pattern = InstructionPattern(
            "push_pop",
            re.compile(r"push\s+([a-z0-9]+).*?pop\s+([a-z0-9]+)", re.DOTALL),
            lambda m: (m.group(1), m.group(2)),
        )

        # Move pattern (mov dst, src)
        mov_pattern = InstructionPattern(
            "mov",
            re.compile(r"mov\s+([a-z0-9]+),\s+([a-z0-9]+)"),
            lambda m: (m.group(2), m.group(1)),  # src, dst
        )

        # Exchange pattern (xchg reg1, reg2)
        xchg_pattern = InstructionPattern(
            "xchg", re.compile(r"xchg\s+([a-z0-9]+),\s+([a-z0-9]+)"), lambda m: (m.group(1), m.group(2))
        )

        self._transfer_rules = [
            TransferRule(push_pop_pattern),
            TransferRule(mov_pattern),
            TransferRule(xchg_pattern, bidirectional=True),
        ]


class X64Architecture(Architecture):
    """x64 (64-bit) architecture implementation."""

    def __init__(self):
        self._register_sets = {
            "32": {"eax", "ebx", "ecx", "edx", "esi", "edi", "esp", "ebp"} | {f"r{i}d" for i in range(8, 16)},
            "64": {"rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp"} | {f"r{i}" for i in range(8, 16)},
        }
        self._setup_transfer_rules()

    @property
    def name(self) -> str:
        return "x64"

    @property
    def register_sets(self) -> Dict[str, Set[str]]:
        return self._register_sets

    @property
    def default_mode(self) -> str:
        return "64"

    @property
    def transfer_rules(self) -> List[TransferRule]:
        return self._transfer_rules

    def get_registers_for_mode(self, mode: Optional[str] = None) -> Set[str]:
        if mode is None:
            # Return all registers for all modes
            all_regs = set()
            for reg_set in self._register_sets.values():
                all_regs.update(reg_set)
            return all_regs
        return self._register_sets.get(mode, set())

    def is_register_compatible(self, reg: str, mode: Optional[str] = None) -> bool:
        if mode is None:
            return reg in self.get_registers_for_mode()
        return reg in self._register_sets.get(mode, set())

    def contains_incompatible_registers(self, instructions: str, mode: Optional[str] = None) -> bool:
        if mode is None:
            return False

        # Check for incompatible register sets
        for mode_name, reg_set in self._register_sets.items():
            if mode_name != mode and self._contains_registers_from_set(instructions, reg_set):
                return True
        return False

    def _setup_transfer_rules(self):
        """Setup transfer rules for x64 instructions."""
        # Push/pop pattern
        push_pop_pattern = InstructionPattern(
            "push_pop",
            re.compile(r"push\s+([a-z0-9]+).*?pop\s+([a-z0-9]+)", re.DOTALL),
            lambda m: (m.group(1), m.group(2)),
        )

        # Move pattern (mov dst, src)
        mov_pattern = InstructionPattern(
            "mov",
            re.compile(r"mov\s+([a-z0-9]+),\s+([a-z0-9]+)"),
            lambda m: (m.group(2), m.group(1)),  # src, dst
        )

        # Exchange pattern (xchg reg1, reg2)
        xchg_pattern = InstructionPattern(
            "xchg", re.compile(r"xchg\s+([a-z0-9]+),\s+([a-z0-9]+)"), lambda m: (m.group(1), m.group(2))
        )

        self._transfer_rules = [
            TransferRule(push_pop_pattern),
            TransferRule(mov_pattern),
            TransferRule(xchg_pattern, bidirectional=True),
        ]


class ARM64Architecture(Architecture):
    """ARM64 (AArch64) architecture implementation."""

    def __init__(self):
        self._register_sets = {
            "32": {f"w{i}" for i in range(31)} | {"wsp", "wzr"},
            "64": {f"x{i}" for i in range(31)} | {"sp", "xzr", "lr"},
        }
        self._setup_transfer_rules()

    @property
    def name(self) -> str:
        return "arm64"

    @property
    def register_sets(self) -> Dict[str, Set[str]]:
        return self._register_sets

    @property
    def default_mode(self) -> str:
        return "64"

    @property
    def transfer_rules(self) -> List[TransferRule]:
        return self._transfer_rules

    def get_registers_for_mode(self, mode: Optional[str] = None) -> Set[str]:
        if mode is None:
            # Return all registers for all modes
            all_regs = set()
            for reg_set in self._register_sets.values():
                all_regs.update(reg_set)
            return all_regs
        return self._register_sets.get(mode, set())

    def is_register_compatible(self, reg: str, mode: Optional[str] = None) -> bool:
        if mode is None:
            return reg in self.get_registers_for_mode()
        return reg in self._register_sets.get(mode, set())

    def contains_incompatible_registers(self, instructions: str, mode: Optional[str] = None) -> bool:
        if mode is None:
            return False

        # Check for incompatible register sets
        for mode_name, reg_set in self._register_sets.items():
            if mode_name != mode and self._contains_registers_from_set(instructions, reg_set):
                return True
        return False

    def _setup_transfer_rules(self):
        """Setup transfer rules for ARM64 instructions."""
        # Move pattern (mov dst, src)
        mov_pattern = InstructionPattern(
            "mov",
            re.compile(r"mov\s+([xw][0-9]+|sp|lr|xzr|wzr),\s+([xw][0-9]+|sp|lr|xzr|wzr)"),
            lambda m: (m.group(2), m.group(1)),  # src, dst
        )

        # Store/Load pair pattern (stp/ldp) - simplified to single transfer
        stp_ldp_pattern = InstructionPattern(
            "stp_ldp",
            re.compile(
                r"stp\s+([xw][0-9]+|sp|lr),\s+([xw][0-9]+|sp|lr),.*?ldp\s+([xw][0-9]+|sp|lr),\s+([xw][0-9]+|sp|lr)",
                re.DOTALL,
            ),
            lambda m: (m.group(1), m.group(3)),  # First stored register to first loaded register
        )

        # Add/subtract with zero (another way to move registers)
        add_zero_pattern = InstructionPattern(
            "add_zero",
            re.compile(r"add\s+([xw][0-9]+|sp),\s+([xw][0-9]+|sp|xzr|wzr),\s+#?0"),
            lambda m: (m.group(2), m.group(1)),  # src, dst
        )

        self._transfer_rules = [TransferRule(mov_pattern), TransferRule(add_zero_pattern)]


# Architecture registry
ARCHITECTURES = {"x86": X86Architecture, "x64": X64Architecture, "arm64": ARM64Architecture}


def get_architecture(arch_name: str) -> Architecture:
    """Get an architecture instance by name."""
    arch_class = ARCHITECTURES.get(arch_name.lower())
    if arch_class is None:
        raise ValueError(f"Unsupported architecture: {arch_name}")
    return arch_class()


def get_available_architectures() -> List[str]:
    """Get list of available architecture names."""
    return list(ARCHITECTURES.keys())
