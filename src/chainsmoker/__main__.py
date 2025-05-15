from .chainsmoker import Chainsmoker
from .parser import parse_args
from .console import CLI


def main():
    console = CLI()
    args = parse_args()

    analyzer = Chainsmoker(
        args.file if not args.list_instructions else None, reg_mode=args.mode, strict_mode=args.strict
    )

    if args.list_instructions:
        analyzer.print_supported_instructions()
        exit()

    if not args.src or not args.dst:
        console.print("[bold red]Error:[/] Source (src) and destination (dst) registers must be specified.")
        console.print("[bold cyan]Usage examples:[/]")
        console.print("  python rop_chain.py gadgets.txt --src rax --dst rcx")
        console.print("  python rop_chain.py gadgets.txt src=rax dst=rcx")
        console.print("  python rop_chain.py --list-instructions # To see supported instructions")
        exit()

    chain = analyzer.find_transfer_chain(args.src, args.dst, args.depth)
    analyzer.print_transfer_chain(chain)

    strict_str = " (strict mode)" if analyzer.strict_mode else ""
    console.print(f"Analyzed [bold green]{len(analyzer.gadgets)}[/] gadgets")
    reg_mode_str = f" ([bold]{analyzer.reg_mode}[/]-bit mode{strict_str})" if analyzer.reg_mode else ""
    console.print(f"Found [bold green]{len(analyzer.register_transfers)}[/] different register transfers{reg_mode_str}")

    if not chain:
        table = Table(title="Available single-step transfers")
        table.add_column("Source", style="cyan")
        table.add_column("Destination", style="green")
        table.add_column("Gadget Count", justify="right", style="yellow")

        for (src, dst), gadgets in analyzer.register_transfers.items():
            table.add_row(src, dst, str(len(gadgets)))

        console.print("\n")
        console.print(table)


if __name__ == "__main__":
    main()
