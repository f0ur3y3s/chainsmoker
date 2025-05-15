from .chainsmoker import Chainsmoker
from .parser import parse_args
from .console import CLIManager


def main():
    cli = CLIManager()
    args = parse_args(cli)

    analyzer = Chainsmoker(
        args.file,
        reg_mode=args.mode,
        strict_mode=args.strict,
    )

    chain = analyzer.find_transfer_chain(args.src, args.dst, args.depth)
    analyzer.print_transfer_chain(chain)

    strict_str = " (strict mode)" if analyzer.strict_mode else ""
    cli.print(f"Analyzed [bold green]{len(analyzer.gadgets)}[/] gadgets")

    reg_mode_str = f" ([bold]{analyzer.reg_mode}[/]-bit mode{strict_str})" if analyzer.reg_mode else ""
    cli.print(f"Found [bold green]{len(analyzer.register_transfers)}[/] different register transfers{reg_mode_str}")

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
