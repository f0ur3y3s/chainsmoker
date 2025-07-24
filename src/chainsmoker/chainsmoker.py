import re
import mmap
from dataclasses import dataclass
from pathlib import Path
from collections import defaultdict, deque
from typing import Optional
from .console import CLIManager
from .architecture import get_architecture, get_available_architectures, Architecture


@dataclass
class Gadget:
    address: str
    instructions: str

    def __post_init__(self):
        self.address = self.address.lower()


class Chainsmoker:
    def __init__(
        self,
        gadget_file: Path,
        architecture: str = "x64",
        reg_mode: Optional[str] = None,
        strict_mode: bool = False,
        verbose: bool = False,
        cli: CLIManager | None = None,
    ):
        """Initialize the Chainsmoker instance.

        Args:
            gadget_file (Path): Path to the gadget file to analyze.
            architecture (str): Architecture name ('x86', 'x64', 'arm64'). Defaults to 'x64'.
            reg_mode (str | None, optional): Register mode specification (e.g., '32', '64'). Defaults to architecture default.
            strict_mode (bool, optional): Only use registers of the specified mode. Defaults to False.
            verbose (bool, optional): Enables verbose output for debugging. Defaults to False.
            cli (CLIManager | None, optional): Console class. Defaults to None.
        """
        self.gadgets = []
        self.register_transfers = defaultdict(list)
        self.gadget_file: Path = gadget_file
        self.architecture: Architecture = get_architecture(architecture)
        self.reg_mode: Optional[str] = reg_mode or self.architecture.default_mode
        self.strict_mode: bool = strict_mode
        self.verbose: bool = verbose
        self.cli = cli if cli else CLIManager()

    def _contains_incompatible_registers(self, instructions: str) -> bool:
        """Check if the instructions contain registers incompatible with the current mode.

        Args:
            instructions (str): The instructions to check.

        Returns:
            bool: True if incompatible registers are found, False otherwise.
        """
        return self.architecture.contains_incompatible_registers(instructions, self.reg_mode)

    def _print_debug(self, message: str) -> None:
        """Print debug messages if verbose mode is enabled.

        Args:
            message (str): The debug message to print.
        """
        if self.verbose:
            self.cli.print(f"[cyan][DEBUG][/cyan] {message}")

    def _should_include_registers(self, reg1: str, reg2: str) -> bool:
        """Check if the registers are compatible with the specified register mode.

        Args:
            reg1 (str): Register name to check.
            reg2 (str): Another register name to check.

        Returns:
            bool: True if both registers are compatible with the specified mode, False otherwise.
        """
        return self.architecture.should_include_registers(reg1, reg2, self.reg_mode)

    def _process_lines(self, lines: list[str], pattern: re.Pattern) -> None:
        """Process lines and extract gadgets using the provided regex pattern."""
        line_count = 0
        parsed_count = 0

        for line in lines:
            line_count += 1
            line = line.strip()

            if not line:
                continue

            if line_count <= 5:
                self._print_debug(f"Sample line {line_count}: {line}")

            match = pattern.match(line)

            if match:
                parsed_count += 1
                address = match.group(1)
                instructions = match.group(2).strip()

                self.gadgets.append(Gadget(address=address, instructions=instructions))

        self._print_debug(f"Read {line_count} lines, parsed {parsed_count} gadgets")

    def parse_gadget_file(self) -> bool:
        try:
            if not self.gadget_file.exists():
                self.cli.print(f"Error: File '{self.gadget_file}' does not exist.", "error")
                return False

            file_size = self.gadget_file.stat().st_size

            if file_size == 0:
                self.cli.print(f"Error: File '{self.gadget_file}' is empty.")
                return False

            self._print_debug(f"Reading file: {self.gadget_file} (Size: {file_size} bytes)")

            gadget_pattern = re.compile(r"(0x[0-9a-fA-F]+):\s+(.*)")

            try:
                with open(self.gadget_file, "rb") as f:
                    header = f.read(4)
                    f.seek(0)

                    if header.startswith(b"\xff\xfe"):
                        encoding = "utf-16-le"
                        offset = 2
                    elif header.startswith(b"\xfe\xff"):
                        encoding = "utf-16-be"
                        offset = 2
                    elif header.startswith(b"\xef\xbb\xbf"):
                        encoding = "utf-8"
                        offset = 3
                    else:
                        encoding = "utf-8"
                        offset = 0

                    # use memory mapping for large files (> 10MB)
                    if file_size > 10 * 1024 * 1024 and hasattr(mmap, "mmap"):
                        with mmap.mmap(
                            f.fileno(),
                            0,
                            access=mmap.ACCESS_READ,
                        ) as mm:
                            content = mm[offset:].decode(encoding, errors="replace")
                    else:
                        content = f.read()[offset:].decode(encoding, errors="replace")

                lines = content.splitlines()
                self._process_lines(lines, gadget_pattern)

                if len(self.gadgets) > 0:
                    self._print_debug(f"Successfully parsed {len(self.gadgets)} gadgets using {encoding} encoding")
                    return True

            except UnicodeDecodeError:
                self._print_debug("Initial encoding detection failed, attempting fallback encodings")

            encodings = ["utf-8", "latin-1", "utf-16", "utf-16-le", "utf-16-be"]

            for encoding in encodings:
                try:
                    self._print_debug(f"Trying encoding: {encoding}")
                    with open(self.gadget_file, "r", encoding=encoding, errors="replace") as f:
                        lines = f.read().splitlines()

                    prev_count = len(self.gadgets)
                    self._process_lines(lines, gadget_pattern)

                    if len(self.gadgets) > prev_count:
                        self._print_debug(
                            f"Successfully parsed {len(self.gadgets) - prev_count} gadgets using {encoding} encoding"
                        )
                        return True

                except UnicodeDecodeError:
                    continue

            if len(self.gadgets) == 0:
                self.cli.print("Warning: No gadgets could be parsed. Check file format.", "warning")
                self.cli.print("Expected format: 0xADDRESS: instruction1; instruction2; ret;")

        except FileNotFoundError:
            self.cli.print(f"Error: File '{self.gadget_file}' not found.", "error")
            return False
        except PermissionError:
            self.cli.print(f"Error: No permission to read file '{self.gadget_file}'.", "error")
            return False
        except Exception as e:
            self.cli.print(f"Error parsing file: {e}", "error")
            return False

        return False

    def build_transfer_graph(self):
        """Build a graph of register transfers based on the gadgets."""
        for gadget in self.gadgets:
            # Use architecture-specific transfer extraction
            transfers = self.architecture.extract_transfers(gadget, self.reg_mode, self.strict_mode)

            for src_reg, dst_reg in transfers:
                self.register_transfers[(src_reg, dst_reg)].append(gadget)

    def find_transfer_chain(
        self,
        src_reg: str,
        dst_reg: str,
        max_depth: int = 5,
        all_solutions: bool = False,
    ) -> list[list[Gadget]]:
        """Find a chain of gadgets to transfer a value from src_reg to dst_reg.

        Args:
            src_reg (str): Source register name
            dst_reg (str): Destination register name
            max_depth (int): Maximum chain length to search
            all_solutions (bool): If True, find all possible solutions instead of just the first one

        Returns:
            A list of gadget chains where each chain is a list of Gadget objects
        """
        self.cli.print(f"Searching for transfer chain: {src_reg} -> {dst_reg} (max depth: {max_depth})")

        if all_solutions:
            self.cli.print("Brute force mode: Finding all possible solutions")

        # Check if registers are compatible with the current architecture and mode
        if not self.architecture.is_register_compatible(src_reg, self.reg_mode):
            self.cli.print(
                f"Error: Register '{src_reg}' is not compatible with {self.architecture.name} {self.reg_mode}-bit mode",
                "error",
            )
            return []

        if not self.architecture.is_register_compatible(dst_reg, self.reg_mode):
            self.cli.print(
                f"Error: Register '{dst_reg}' is not compatible with {self.architecture.name} {self.reg_mode}-bit mode",
                "error",
            )
            return []

        if src_reg == dst_reg:
            self.cli.print("Source and destination registers are the same, no transfer needed.", "warning")
            return []

        all_chains = []

        if (src_reg, dst_reg) in self.register_transfers:
            self.cli.print(f"Found direct transfer: {src_reg} -> {dst_reg}", "success")
            if all_solutions:
                for gadget in self.register_transfers[(src_reg, dst_reg)]:
                    all_chains.append([gadget])
                return all_chains
            else:
                return [[self.register_transfers[(src_reg, dst_reg)][0]]]

        queue = deque([(src_reg, [])])

        while queue:
            current_reg, path = queue.popleft()

            if len(path) >= max_depth:
                continue

            path_visited = set([reg for reg, _ in path]) if path else set()
            path_visited.add(current_reg)

            if len(path) == 0:
                self._print_debug(f"Exploring from {current_reg} (current path: start)")
            else:
                path_str = " -> ".join([f"{src}→{dst}@{g.address}" for (src, dst), g in path])
                self._print_debug(f"Exploring from {current_reg} (current path: {path_str})")

            found_next = False

            for next_reg_pair, gadgets in self.register_transfers.items():
                if next_reg_pair[0] == current_reg:
                    next_reg = next_reg_pair[1]

                    if next_reg in path_visited:
                        continue

                    found_next = True

                    for gadget in gadgets:
                        new_path = path + [((current_reg, next_reg), gadget)]
                        self._print_debug(f"Found transfer: {current_reg} -> {next_reg}")

                        if next_reg == dst_reg:
                            gadget_chain = [g for _, g in new_path]
                            self._print_debug(f"Found path: {src_reg} -> {dst_reg} with {len(gadget_chain)} gadgets")
                            all_chains.append(gadget_chain)

                            if not all_solutions:
                                return [gadget_chain]
                        else:
                            queue.append((next_reg, new_path))

            if not found_next:
                self._print_debug(f"No outgoing transfers from {current_reg}")

        if not all_chains:
            self.cli.print(f"No path found from {src_reg} to {dst_reg} within depth {max_depth}", "warning")
            return []

        all_chains.sort(key=len)

        self.cli.print(f"Found {len(all_chains)} different paths from {src_reg} to {dst_reg}", "success")
        return all_chains

    def print_transfer_chain(self, chains):
        """Print a formatted table of gadget chains.

        Args:
            chains: A list of gadget chains, where each chain is a list of Gadget objects
        """
        if not chains:
            self.cli.print("No valid transfer chain found.", style="error")
            return

        if isinstance(chains, Gadget):
            chains = [[chains]]
        elif chains and isinstance(chains[0], Gadget):
            chains = [chains]

        for i, chain in enumerate(chains):
            if not chain:
                continue

            if i > 0:
                self.cli.print("\n" + "=" * 80 + "\n")

            self.cli.print(f"Solution {i + 1} of {len(chains)} (length: {len(chain)} gadgets)", style="success")

            table = self.cli.create_table(
                f"Transfer Chain #{i + 1}",
                [
                    ("Step", "header", "center"),
                    ("Address", "title", "left"),
                    ("Instructions", "default", "left"),
                    ("Warnings", "error", "left"),
                ],
                expand=True,
                border_style="success",
            )

            for j, gadget in enumerate(chain):
                warning = ""

                if self.reg_mode and self._contains_incompatible_registers(gadget.instructions):
                    warning = f"[yellow]Instructions may contain registers incompatible with {self.architecture.name} {self.reg_mode}-bit mode[/yellow]"

                address = f"[bold blue]{gadget.address}[/bold blue]"

                instructions = gadget.instructions
                # Highlight common instruction types
                instructions = re.sub(
                    r"\b(mov|push|pop|xchg|stp|ldp|add|sub)\b", r"[bold green]\1[/bold green]", instructions
                )

                # Highlight registers from all register sets for this architecture
                all_regs = self.architecture.get_registers_for_mode()
                for reg in sorted(all_regs, key=len, reverse=True):  # Sort by length to avoid partial matches
                    instructions = re.sub(r"\b" + re.escape(reg) + r"\b", r"[cyan]\g<0>[/cyan]", instructions)

                table.add_row(f"{j + 1}", address, instructions, warning)

            self.cli.config.console.print(table)

            if self.verbose:
                summary = f"Chain length: {len(chain)} gadgets"
                self.cli.print(f"[dim][italic]{summary}[/italic][/dim]")
