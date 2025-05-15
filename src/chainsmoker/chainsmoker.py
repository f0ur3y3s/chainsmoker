import re
import os
from collections import defaultdict, deque


class Chainsmoker:
    def __init__(self, gadget_file, reg_mode=None, strict_mode=False):
        self.gadgets = []
        self.register_transfers = defaultdict(list)
        self.reg_mode = reg_mode  # Can be "32" for 32-bit or "64" for 64-bit registers, or None for all
        self.strict_mode = strict_mode  # If True, enforce strict register size consistency
        if gadget_file:  # Only parse if a file is provided
            self.parse_gadget_file(gadget_file)
            self.build_transfer_graph()

    def _contains_32bit_ops(self, instructions, reg32_set):
        """Check if the instructions contain 32-bit operations that would be incompatible with 64-bit mode."""
        # Look for any 32-bit register in the instruction
        for reg in reg32_set:
            # Check for the register as a whole word
            if re.search(r"\b" + reg + r"\b", instructions):
                return True
        return False

    def _contains_64bit_ops(self, instructions, reg64_set):
        """Check if the instructions contain 64-bit operations that would be incompatible with 32-bit mode."""
        # Look for any 64-bit register in the instruction
        for reg in reg64_set:
            # Check for the register as a whole word (not part of another register name)
            if re.search(r"\b" + reg + r"\b", instructions):
                return True
        return False

    def parse_gadget_file(self, filepath):
        """Parse the gadget file and extract gadget information."""
        try:
            # Check if file exists
            if not os.path.exists(filepath):
                print(f"Error: File '{filepath}' does not exist.")
                exit()

            # Check file size
            file_size = os.path.getsize(filepath)
            if file_size == 0:
                print(f"Error: File '{filepath}' is empty.")
                exit()

            print(f"Reading file: {filepath} (Size: {file_size} bytes)")

            # Try different encoding methods
            encodings = ["utf-8", "utf-16", "utf-16-le", "utf-16-be", "latin-1"]

            for encoding in encodings:
                try:
                    print(f"Trying encoding: {encoding}")
                    with open(filepath, "r", encoding=encoding, errors="replace") as f:
                        line_count = 0
                        parsed_count = 0
                        content = f.read()

                        # Remove BOM if present
                        if content.startswith("\ufeff"):
                            content = content[1:]

                        lines = content.splitlines()

                        for line in lines:
                            line_count += 1
                            line = line.strip()
                            if not line:
                                continue

                            # Print first few lines for debugging
                            if line_count <= 5:
                                print(f"Sample line {line_count}: {line}")

                            # Extract address and instructions
                            match = re.match(r"(0x[0-9a-fA-F]+):\s+(.*)", line)
                            if match:
                                parsed_count += 1
                                address = match.group(1)
                                instructions = match.group(2).strip()
                                self.gadgets.append({"address": address, "instructions": instructions})

                        if parsed_count > 0:
                            print(f"Successfully parsed {parsed_count} gadgets using {encoding} encoding")
                            break
                except UnicodeDecodeError:
                    continue

            if len(self.gadgets) == 0:
                print("Warning: No gadgets could be parsed. Here's another approach:")

                # Try binary mode and handle byte by byte
                with open(filepath, "rb") as f:
                    content = f.read()

                    # Strip BOM if present
                    if content.startswith(b"\xff\xfe"):
                        content = content[2:]
                    elif content.startswith(b"\xfe\xff"):
                        content = content[2:]
                    elif content.startswith(b"\xef\xbb\xbf"):
                        content = content[3:]

                    # Convert to string, ignoring errors
                    text = content.decode("utf-8", errors="ignore")
                    lines = text.splitlines()

                    line_count = 0
                    parsed_count = 0

                    for line in lines:
                        line_count += 1
                        line = line.strip()
                        if not line:
                            continue

                        # Print first few lines for debugging
                        if line_count <= 5:
                            print(f"Sample line {line_count}: {line}")

                        # Extract address and instructions
                        match = re.match(r"(0x[0-9a-fA-F]+):\s+(.*)", line)
                        if match:
                            parsed_count += 1
                            address = match.group(1)
                            instructions = match.group(2).strip()
                            self.gadgets.append({"address": address, "instructions": instructions})

                    print(f"Read {line_count} lines, parsed {parsed_count} gadgets using binary approach")

            if len(self.gadgets) == 0:
                print("Warning: No gadgets could be parsed. Check file format.")
                print("Expected format: 0xADDRESS: instruction1; instruction2; ret;")

        except FileNotFoundError:
            print(f"Error: File '{filepath}' not found.")
            exit()
        except PermissionError:
            print(f"Error: No permission to read file '{filepath}'.")
            exit()
        except Exception as e:
            print(f"Error parsing file: {e}")
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
        print(f"Searching for transfer chain: {src_reg} -> {dst_reg} (max depth: {max_depth})")

        # Check if registers match the selected mode
        reg32_set = set(["eax", "ebx", "ecx", "edx", "esi", "edi", "esp", "ebp"] + [f"r{i}d" for i in range(8, 16)])
        reg64_set = set(["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp"] + [f"r{i}" for i in range(8, 16)])

        if self.reg_mode == "32" and (src_reg not in reg32_set or dst_reg not in reg32_set):
            print(f"Error: In 32-bit mode, must use 32-bit registers (e.g., eax, ecx)")
            return []

        if self.reg_mode == "64" and (src_reg not in reg64_set or dst_reg not in reg64_set):
            print(f"Error: In 64-bit mode, must use 64-bit registers (e.g., rax, rcx)")
            return []

        if src_reg == dst_reg:
            print("Source and destination registers are the same, no transfer needed.")
            return []

        # Direct transfer
        if (src_reg, dst_reg) in self.register_transfers:
            print(f"Found direct transfer: {src_reg} -> {dst_reg}")
            return self.register_transfers[(src_reg, dst_reg)]

        # BFS to find a path
        visited = set()
        queue = deque([(src_reg, [])])

        while queue:
            current_reg, path = queue.popleft()

            if len(path) >= max_depth:
                continue

            visited.add(current_reg)

            # Debug output for explored paths
            if len(path) == 0:
                print(f"Exploring from {current_reg} (current path: start)")
            else:
                path_str = " -> ".join([g["address"] for g in path])
                print(f"Exploring from {current_reg} (current path: {path_str})")

            found_next = False
            for next_reg_pair, gadgets in self.register_transfers.items():
                if next_reg_pair[0] == current_reg and next_reg_pair[1] not in visited:
                    found_next = True
                    next_reg = next_reg_pair[1]
                    new_path = path + [gadgets[0]]  # Just use the first gadget for simplicity

                    if next_reg == dst_reg:
                        print(f"Found path: {src_reg} -> {next_reg}")
                        return new_path

                    queue.append((next_reg, new_path))

            if not found_next:
                print(f"No outgoing transfers from {current_reg}")

        print(f"No path found from {src_reg} to {dst_reg} within depth {max_depth}")
        return []

    def print_transfer_chain(self, chain):
        """Print a formatted chain of gadgets."""
        if not chain:
            print("No valid transfer chain found.")
            return

        print("Transfer Chain:")
        print("-" * 50)
        for i, gadget in enumerate(chain):
            print(f"Step {i + 1}: {gadget['address']} - {gadget['instructions']}")

            # Add a warning if gadget appears to mix register sizes
            if self.reg_mode:
                reg32_set = set(
                    ["eax", "ebx", "ecx", "edx", "esi", "edi", "esp", "ebp"] + [f"r{i}d" for i in range(8, 16)]
                )
                reg64_set = set(
                    ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp"] + [f"r{i}" for i in range(8, 16)]
                )

                if self.reg_mode == "64" and self._contains_32bit_ops(gadget["instructions"], reg32_set):
                    print(f"  WARNING: This gadget uses 32-bit registers which may zero extend to 64-bit")
                elif self.reg_mode == "32" and self._contains_64bit_ops(gadget["instructions"], reg64_set):
                    print(f"  WARNING: This gadget uses 64-bit registers which may be incompatible with 32-bit mode")
        print("-" * 50)

    def _should_include_registers(self, reg1, reg2, reg32_set, reg64_set):
        """Determine if registers should be included based on bitness mode."""
        if self.reg_mode == "32":
            return reg1 in reg32_set and reg2 in reg32_set
        elif self.reg_mode == "64":
            return reg1 in reg64_set and reg2 in reg64_set
        else:
            return True  # Include all if no mode specified

    def print_supported_instructions(self):
        """Print the types of instructions supported by the analyzer."""
        print("Supported Instructions:")
        print("-" * 50)
        print("- mov reg1, reg2    : Move value from reg2 to reg1")
        print("- push reg1; pop reg2: Transfer value from reg1 to reg2")
        print("- xchg reg1, reg2   : Exchange values between reg1 and reg2")

        if self.reg_mode == "32":
            print("\nCurrent mode: 32-bit registers only")
            print("Supported registers: eax, ebx, ecx, edx, esi, edi, esp, ebp, r8d-r15d")
        elif self.reg_mode == "64":
            print("\nCurrent mode: 64-bit registers only")
            print("Supported registers: rax, rbx, rcx, rdx, rsi, rdi, rsp, rbp, r8-r15")
        else:
            print("\nCurrent mode: All registers (both 32-bit and 64-bit)")

        if self.strict_mode:
            print("\nStrict mode: ON (rejecting gadgets that mix register sizes)")

        print("-" * 50)

