from pathlib import Path
from .chainsmoker import Chainsmoker
from .parser import parse_args
from .console import CLIManager


def main():
    cli = CLIManager()
    args = parse_args(cli)

    # Convert old mode parameter to new architecture and reg_mode
    architecture = getattr(args, "arch", "x64")  # Default to x64
    reg_mode = None

    # Handle backward compatibility with --mode flag
    if hasattr(args, "mode") and args.mode:
        if args.mode == 32:
            architecture = "x86"
            reg_mode = "32"
        elif args.mode == 64:
            architecture = "x64"
            reg_mode = "64"

    # Override with --arch if provided
    if hasattr(args, "arch") and args.arch:
        architecture = args.arch

    analyzer = Chainsmoker(
        Path(args.file),
        architecture=architecture,
        reg_mode=reg_mode,
        strict_mode=args.strict,
        verbose=args.verbose,
        cli=cli,
    )

    analyzer.parse_gadget_file()
    analyzer.build_transfer_graph()

    chain = analyzer.find_transfer_chain(args.src, args.dst, args.depth, args.all)
    analyzer.print_transfer_chain(chain)

    strict_str = " (strict mode)" if analyzer.strict_mode else ""
    cli.print(f"Analyzed [bold green]{len(analyzer.gadgets)}[/] gadgets")

    arch_str = f" ([bold]{analyzer.architecture.name}[/] architecture"
    reg_mode_str = f", {analyzer.reg_mode}-bit mode{strict_str})" if analyzer.reg_mode else ")"
    cli.print(
        f"Found [bold green]{len(analyzer.register_transfers)}[/] different register transfers{arch_str}{reg_mode_str}"
    )

    if not chain:
        table = cli.create_table(
            "Available single-step transfers",
            [
                ("Source", "title", "left"),
                ("Destination", "success", "left"),
                ("Gadget Count", "header", "right"),
            ],
            expand=False,
        )

        sorted_transfers = sorted(
            analyzer.register_transfers.items(),
            key=lambda item: len(item[1]),
            reverse=True,
        )

        for (src, dst), gadgets in sorted_transfers:
            table.add_row(src, dst, str(len(gadgets)))

        cli.print("\n")
        cli.config.console.print(table)


if __name__ == "__main__":
    main()
