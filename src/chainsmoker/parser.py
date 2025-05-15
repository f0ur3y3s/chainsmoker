import argparse
from typing import Optional
from pathlib import Path
from chainsmoker.console import CLIManager


def parse_args(cli: Optional[CLIManager] = None):
    if cli is None:
        cli = CLIManager()

    parser = argparse.ArgumentParser(
        description="Chainsmoker: ROP gadget chain generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False,
    )

    parser.add_argument("file", nargs="?", type=str, help="Gadget file to analyze")
    parser.add_argument("--src", "-s", type=str, help="Source register")
    parser.add_argument("--dst", "-d", type=str, help="Destination register")

    parser.add_argument(
        "--mode",
        "-m",
        type=int,
        choices=[32, 64],
        default=64,
        help="Register mode: 32 or 64 bit",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Strict mode: only consider exact register sizes",
    )
    parser.add_argument(
        "--depth",
        type=int,
        default=5,
        help="Maximum chain depth to search",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose output",
    )
    parser.add_argument(
        "--help",
        "-h",
        action="store_true",
        help="Show this help message and exit",
    )

    args = parser.parse_args()

    if args.help:
        show_help(cli, parser)
        exit(0)

    if not args.file:
        cli.print("[bold red]Error:[/] No gadget file specified", style="error")
        show_help(cli, parser)
        exit(1)

    if args.file and not Path(args.file).exists():
        cli.print(f"[bold red]Error:[/] File not found: {args.file}", style="error")
        exit(1)

    if args.src is None:
        cli.print("[bold red]Error:[/] No source register specified", style="error")
        show_help(cli, parser)
        exit(1)

    if args.dst is None:
        cli.print("[bold red]Error:[/] No destination register specified", style="error")
        show_help(cli, parser)
        exit(1)

    if args.src == args.dst:
        cli.print("[bold red]Error:[/] Source and destination registers cannot be the same", style="error")
        show_help(cli, parser)
        exit(1)

    if args.depth < 1:
        cli.print("[bold red]Error:[/] Chain depth must be at least 1", style="error")
        show_help(cli, parser)
        exit(1)

    return args


def show_help(cli: CLIManager, parser: argparse.ArgumentParser):
    help_text = (
        "\n[italic green]Usage:[/]\n"
        "  chainsmoker <options> gadget_file.txt --src rax --dst rbx\n"
        "  chainsmoker <options> gadget_file.txt src=rax dst=rbx\n"
    )

    cli.print(help_text, indent=0)

    options_table = cli.create_table(
        "",
        [
            ("Option", "title", "left"),
            ("Description", "default", "left"),
            ("Default", "header", "center"),
        ],
        border_style="default",
        header_style="default",
    )

    for action in parser._actions:
        if action.dest == "help":
            continue

        flags = []

        for opt in action.option_strings:
            flags.append(opt)

        if not flags and action.dest != "help":
            flags = [f"<{action.dest}>"]

        flag_str = ", ".join(flags)

        help_text = action.help or ""

        default_val = ""
        if action.default not in [None, argparse.SUPPRESS] and action.default != "":
            if action.default is True:
                default_val = "True"
            elif action.default is False:
                default_val = "False"
            else:
                default_val = str(action.default)

        if action.choices:
            help_text += f" (choices: {', '.join(map(str, action.choices))})"

        if action.required:
            help_text = "[Required] " + help_text

        options_table.add_row(flag_str, help_text, default_val)

    cli.config.console.print(options_table)


if __name__ == "__main__":
    cli = CLIManager()
    args = parse_args(cli)
    cli.print(f"Parsed arguments: {args}")
