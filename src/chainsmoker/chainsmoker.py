import re
import os
from pathlib import Path
from collections import defaultdict, deque
from .console import CLIManager


class Chainsmoker:
    def __init__(
        self,
        gadget_file: Path,
        reg_mode: str | None = None,
        strict_mode: bool = False,
        verbose: bool = False,
        cli: CLIManager | None = None,
    ):
        self.gadgets = []
        self.register_transfers = defaultdict(list)
        self.reg_mode = reg_mode
        self.strict_mode = strict_mode
        self.gadget_file: Path = gadget_file
        self.verbose = verbose
        self.cli = cli if cli else CLIManager()

    def _contains_32bit_ops(self, instructions: str, reg32_set: set[str]) -> bool:
        """Check if the instructions contain 32-bit operations that would be incompatible with 64-bit mode

        Args:
            instructions (str): The instructions to check.
            reg32_set (set[str]): The set of 32-bit registers.

        Returns:
            bool: True if 32-bit operations are found, False otherwise.
        """
        for reg in reg32_set:
            # Check for the register as a whole word
            if re.search(r"\b" + reg + r"\b", instructions):
                return True
        return False

    def _contains_64bit_ops(self, instructions: str, reg64_set: set[str]) -> bool:
        """Check if the instructions contain 64-bit operations that would be incompatible with 32-bit mode

        Args:
            instructions (str): The instructions to check.
            reg64_set (set[str]): The set of 64-bit registers.

        Returns:
            bool: True if 64-bit operations are found, False otherwise.
        """
        for reg in reg64_set:
            # Check for the register as a whole word (not part of another register name)
            if re.search(r"\b" + reg + r"\b", instructions):
                return True
        return False

    def _print_debug(self, message):
        """Print debug messages if verbose mode is enabled."""
        if self.verbose:
            self.cli.print(f"[cyan][DEBUG][/cyan] {message}")

    def parse_gadget_file(self):
        """Parse the gadget file and extract gadget information."""
        try:
            if not self.gadget_file.exists():
                self.cli.print(f"Error: File '{self.gadget_file}' does not exist.", "error")
                exit()

            file_size = self.gadget_file.stat().st_size

            if file_size == 0:
                self.cli.print(f"Error: File '{self.gadget_file}' is empty.")
                exit()

            self._print_debug(f"Reading file: {self.gadget_file} (Size: {file_size} bytes)")

            encodings = ["utf-8", "utf-16", "utf-16-le", "utf-16-be", "latin-1"]

            for encoding in encodings:
                try:
                    self._print_debug(f"Trying encoding: {encoding}")
                    with open(self.gadget_file, "r", encoding=encoding, errors="replace") as f:
                        line_count = 0
                        parsed_count = 0
                        content = f.read()

                        if content.startswith("\ufeff"):
                            content = content[1:]

                        lines = content.splitlines()

                        for line in lines:
                            line_count += 1
                            line = line.strip()
                            if not line:
                                continue

                            if line_count <= 5:
                                self._print_debug(f"Sample line {line_count}: {line}")

                            match = re.match(r"(0x[0-9a-fA-F]+):\s+(.*)", line)

                            if match:
                                parsed_count += 1
                                address = match.group(1)
                                instructions = match.group(2).strip()
                                self.gadgets.append({"address": address, "instructions": instructions})

                        if parsed_count > 0:
                            self._print_debug(f"Successfully parsed {parsed_count} gadgets using {encoding} encoding")
                            break

                except UnicodeDecodeError:
                    continue

            if len(self.gadgets) == 0:
                self.cli.print("Warning: No gadgets could be parsed, attempting binary mode.", "warning")

                with open(self.gadget_file, "rb") as f:
                    content = f.read()

                    if content.startswith(b"\xff\xfe"):
                        content = content[2:]
                    elif content.startswith(b"\xfe\xff"):
                        content = content[2:]
                    elif content.startswith(b"\xef\xbb\xbf"):
                        content = content[3:]

                    text = content.decode("utf-8", errors="ignore")
                    lines = text.splitlines()

                    line_count = 0
                    parsed_count = 0

                    for line in lines:
                        line_count += 1
                        line = line.strip()

                        if not line:
                            continue

                        if line_count <= 5:
                            self._print_debug(f"Sample line {line_count}: {line}")

                        match = re.match(r"(0x[0-9a-fA-F]+):\s+(.*)", line)

                        if match:
                            parsed_count += 1
                            address = match.group(1)
                            instructions = match.group(2).strip()
                            self.gadgets.append({"address": address, "instructions": instructions})

                    self._print_debug(f"Read {line_count} lines, parsed {parsed_count} gadgets using binary approach")

            if len(self.gadgets) == 0:
                self.cli.print("Warning: No gadgets could be parsed. Check file format.", "warning")
                self.cli.print("Expected format: 0xADDRESS: instruction1; instruction2; ret;")

        except FileNotFoundError:
            self.cli.print(f"Error: File '{self.gadget_file}' not found.", "error")
            exit()
        except PermissionError:
            self.cli.print(f"Error: No permission to read file '{self.gadget_file}'.", "error")
            exit()
        except Exception as e:
            self.cli.print(f"Error parsing file: {e}", "error")
            exit()

    def build_transfer_graph(self):
        """Build a graph of register transfers based on the gadgets."""
        # Define register sets for filtering
        reg32_set = set(["eax", "ebx", "ecx", "edx", "esi", "edi", "esp", "ebp"] + [f"r{i}d" for i in range(8, 16)])
        reg64_set = set(["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp"] + [f"r{i}" for i in range(8, 16)])

        for gadget in self.gadgets:
            instructions = gadget["instructions"]
            address = gadget["address"]

            # In strict mode, reject gadgets that mix register sizes
            if self.strict_mode:
                has_32bit = self._contains_32bit_ops(instructions, reg32_set)
                has_64bit = self._contains_64bit_ops(instructions, reg64_set)
                if has_32bit and has_64bit:
                    continue

            # Skip instructions that contain register-size mismatches if mode is set
            if self.reg_mode == "64" and self.strict_mode and self._contains_32bit_ops(instructions, reg32_set):
                continue

            if self.reg_mode == "32" and self.strict_mode and self._contains_64bit_ops(instructions, reg64_set):
                continue

            # Look for direct register transfers (push/pop, mov)
            # push src; pop dst pattern
            if "push" in instructions and "pop" in instructions:
                src_match = re.search(r"push\s+([a-z0-9]+)", instructions)
                dst_match = re.search(r"pop\s+([a-z0-9]+)", instructions)
                if src_match and dst_match:
                    src_reg = src_match.group(1)
                    dst_reg = dst_match.group(1)

                    # Apply register size filtering if specified
                    if self._should_include_registers(src_reg, dst_reg, reg32_set, reg64_set):
                        self.register_transfers[(src_reg, dst_reg)].append(gadget)

            # mov dst, src pattern
            mov_matches = re.findall(r"mov\s+([a-z0-9]+),\s+([a-z0-9]+)", instructions)
            for match in mov_matches:
                dst_reg = match[0]
                src_reg = match[1]

                # Apply register size filtering if specified
                if self._should_include_registers(src_reg, dst_reg, reg32_set, reg64_set):
                    self.register_transfers[(src_reg, dst_reg)].append(gadget)

            # Add support for xchg instruction
            # xchg reg1, reg2 or xchg reg2, reg1 (both are equivalent)
            xchg_matches = re.findall(r"xchg\s+([a-z0-9]+),\s+([a-z0-9]+)", instructions)
            for match in xchg_matches:
                reg1 = match[0]
                reg2 = match[1]

                # Apply register size filtering if specified
                if self._should_include_registers(reg1, reg2, reg32_set, reg64_set):
                    # Add both directions since xchg swaps both registers
                    self.register_transfers[(reg1, reg2)].append(gadget)
                    self.register_transfers[(reg2, reg1)].append(gadget)

            # Check for direct register moves with different instruction variants
            if instructions.endswith("ret;"):
                # Handle cases like "mov edi, edx; ret;" for 32-bit portions of registers
                for reg32 in ["eax", "ebx", "ecx", "edx", "esi", "edi"]:
                    for reg32_src in ["eax", "ebx", "ecx", "edx", "esi", "edi"]:
                        pattern = f"mov {reg32}, {reg32_src};"
                        if pattern in instructions:
                            # Map 32-bit registers to their 64-bit equivalents for graph building
                            reg64_map = {
                                "eax": "rax",
                                "ebx": "rbx",
                                "ecx": "rcx",
                                "edx": "rdx",
                                "esi": "rsi",
                                "edi": "rdi",
                            }
                            src_reg64 = reg64_map.get(reg32_src, reg32_src)
                            dst_reg64 = reg64_map.get(reg32, reg32)

                            # For 32-bit mode, keep the original registers
                            # For 64-bit mode, use the mapped registers
                            if self.reg_mode == "32":
                                if self._should_include_registers(reg32_src, reg32, reg32_set, reg64_set):
                                    self.register_transfers[(reg32_src, reg32)].append(gadget)
                            elif self.reg_mode == "64":
                                if self._should_include_registers(src_reg64, dst_reg64, reg32_set, reg64_set):
                                    self.register_transfers[(src_reg64, dst_reg64)].append(gadget)
                            else:
                                # No mode specified, include both
                                if reg32_src in reg32_set and reg32 in reg32_set:
                                    self.register_transfers[(reg32_src, reg32)].append(gadget)
                                if src_reg64 in reg64_set and dst_reg64 in reg64_set:
                                    self.register_transfers[(src_reg64, dst_reg64)].append(gadget)

                        # Also handle xchg for 32-bit registers
                        pattern = f"xchg {reg32}, {reg32_src};"
                        if pattern in instructions:
                            reg64_map = {
                                "eax": "rax",
                                "ebx": "rbx",
                                "ecx": "rcx",
                                "edx": "rdx",
                                "esi": "rsi",
                                "edi": "rdi",
                            }
                            reg1_64 = reg64_map.get(reg32, reg32)
                            reg2_64 = reg64_map.get(reg32_src, reg32_src)

                            # For 32-bit mode, keep the original registers
                            # For 64-bit mode, use the mapped registers
                            if self.reg_mode == "32":
                                if self._should_include_registers(reg32, reg32_src, reg32_set, reg64_set):
                                    self.register_transfers[(reg32, reg32_src)].append(gadget)
                                    self.register_transfers[(reg32_src, reg32)].append(gadget)
                            elif self.reg_mode == "64":
                                if self._should_include_registers(reg1_64, reg2_64, reg32_set, reg64_set):
                                    self.register_transfers[(reg1_64, reg2_64)].append(gadget)
                                    self.register_transfers[(reg2_64, reg1_64)].append(gadget)
                            else:
                                # No mode specified, include both
                                if reg32 in reg32_set and reg32_src in reg32_set:
                                    self.register_transfers[(reg32, reg32_src)].append(gadget)
                                    self.register_transfers[(reg32_src, reg32)].append(gadget)
                                if reg1_64 in reg64_set and reg2_64 in reg64_set:
                                    self.register_transfers[(reg1_64, reg2_64)].append(gadget)
                                    self.register_transfers[(reg2_64, reg1_64)].append(gadget)

                # Handle r8-r15 registers explicitly
                for i in range(8, 16):
                    for j in range(8, 16):
                        src_reg = f"r{i}"
                        dst_reg = f"r{j}"

                        # Only process if the registers match our bitness mode
                        if self._should_include_registers(src_reg, dst_reg, reg32_set, reg64_set):
                            # Check for mov instruction
                            pattern = f"mov {dst_reg}, {src_reg};"
                            if pattern in instructions:
                                self.register_transfers[(src_reg, dst_reg)].append(gadget)

                            # Check for xchg instruction
                            pattern = f"xchg {src_reg}, {dst_reg};"
                            if pattern in instructions:
                                self.register_transfers[(src_reg, dst_reg)].append(gadget)
                                self.register_transfers[(dst_reg, src_reg)].append(gadget)

                            # Check for reverse order of xchg
                            pattern = f"xchg {dst_reg}, {src_reg};"
                            if pattern in instructions:
                                self.register_transfers[(src_reg, dst_reg)].append(gadget)
                                self.register_transfers[(dst_reg, src_reg)].append(gadget)

    def find_transfer_chain(self, src_reg, dst_reg, max_depth=5):
        """Find a chain of gadgets to transfer a value from src_reg to dst_reg."""
        self.cli.print(f"Searching for transfer chain: {src_reg} -> {dst_reg} (max depth: {max_depth})")

        # Check if registers match the selected mode
        reg32_set = set(["eax", "ebx", "ecx", "edx", "esi", "edi", "esp", "ebp"] + [f"r{i}d" for i in range(8, 16)])
        reg64_set = set(["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp"] + [f"r{i}" for i in range(8, 16)])

        if self.reg_mode == "32" and (src_reg not in reg32_set or dst_reg not in reg32_set):
            self.cli.print(f"Error: In 32-bit mode, must use 32-bit registers (e.g., eax, ecx)", "error")
            return []

        if self.reg_mode == "64" and (src_reg not in reg64_set or dst_reg not in reg64_set):
            self.cli.print(f"Error: In 64-bit mode, must use 64-bit registers (e.g., rax, rcx)", "error")
            return []

        if src_reg == dst_reg:
            self.cli.print("Source and destination registers are the same, no transfer needed.", "warning")
            return []

        if (src_reg, dst_reg) in self.register_transfers:
            self.cli.print(f"Found direct transfer: {src_reg} -> {dst_reg}", "success")
            return self.register_transfers[(src_reg, dst_reg)]

        visited = set()
        queue = deque([(src_reg, [])])

        while queue:
            current_reg, path = queue.popleft()

            if len(path) >= max_depth:
                continue

            visited.add(current_reg)

            if len(path) == 0:
                self._print_debug(f"Exploring from {current_reg} (current path: start)")
            else:
                path_str = " -> ".join([g["address"] for g in path])
                self._print_debug(f"Exploring from {current_reg} (current path: {path_str})")

            found_next = False

            for next_reg_pair, gadgets in self.register_transfers.items():
                if next_reg_pair[0] == current_reg and next_reg_pair[1] not in visited:
                    found_next = True
                    next_reg = next_reg_pair[1]
                    new_path = path + [gadgets[0]]
                    self._print_debug(f"Found transfer: {current_reg} -> {next_reg}")

                    if next_reg == dst_reg:
                        self._print_debug(f"Found path: {src_reg} -> {next_reg}")
                        return new_path

                    queue.append((next_reg, new_path))

            if not found_next:
                self._print_debug(f"No outgoing transfers from {current_reg}")

        self.cli.print(f"No path found from {src_reg} to {dst_reg} within depth {max_depth}", "warning")
        return []

    def print_transfer_chain(self, chain):
        """Print a formatted table of gadget chain."""
        if not chain:
            self.cli.print("No valid transfer chain found.", style="error")
            return

        table = self.cli.create_table(
            "Transfer Chain",
            [
                ("Step", "header", "center"),
                ("Address", "title", "left"),
                ("Instructions", "default", "left"),
                ("Warnings", "error", "left"),
            ],
            expand=True,
            border_style="success",
        )

        reg32_set = set(["eax", "ebx", "ecx", "edx", "esi", "edi", "esp", "ebp"] + [f"r{i}d" for i in range(8, 16)])
        reg64_set = set(["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp"] + [f"r{i}" for i in range(8, 16)])

        for i, gadget in enumerate(chain):
            warning = ""

            if self.reg_mode:
                if self.reg_mode == "64" and self._contains_32bit_ops(gadget["instructions"], reg32_set):
                    warning = "[yellow]32-bit registers may zero extend to 64-bit[/yellow]"
                elif self.reg_mode == "32" and self._contains_64bit_ops(gadget["instructions"], reg64_set):
                    warning = "[yellow]64-bit registers may be incompatible with 32-bit mode[/yellow]"

            address = f"[bold blue]{gadget['address']}[/bold blue]"

            instructions = gadget["instructions"]
            instructions = re.sub(r"\b(mov|push|pop|xchg)\b", r"[bold green]\1[/bold green]", instructions)

            for reg in reg32_set | reg64_set:
                instructions = re.sub(r"\b" + reg + r"\b", r"[cyan]\g<0>[/cyan]", instructions)

            table.add_row(f"{i + 1}", address, instructions, warning)

        self.cli.config.console.print(table)

        if self.verbose:
            summary = f"Chain length: {len(chain)} gadgets"
            self.cli.print(f"[dim][italic]{summary}[/italic][/dim]")

    def _should_include_registers(self, reg1, reg2, reg32_set, reg64_set):
        """Determine if registers should be included based on bitness mode."""
        if self.reg_mode == "32":
            return reg1 in reg32_set and reg2 in reg32_set
        elif self.reg_mode == "64":
            return reg1 in reg64_set and reg2 in reg64_set
        else:
            return True
