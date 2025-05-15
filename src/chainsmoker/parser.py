from argparse import ArgumentParser, Namespace


def parse_args() -> Namespace:
    parser = ArgumentParser(description="Find ROP gadget chains to transfer values between registers.")
    parser.add_argument("file", nargs="?", help="Path to the file containing ROP gadgets")
    parser.add_argument("-s", "--src", dest="src", help="Source register (e.g., rax, r8)")
    parser.add_argument("-d", "--dst", dest="dst", help="Destination register (e.g., rcx, r9)")
    parser.add_argument("--depth", type=int, default=3, help="Maximum chain depth (default: 3)")
    parser.add_argument("--list-instructions", action="store_true", help="List supported instructions")
    parser.add_argument(
        "-m",
        "--mode",
        choices=["32", "64"],
        help="Register size mode: 32-bit or 64-bit registers only",
    )
    parser.add_argument("--strict", action="store_true", help="Strict mode: reject any gadgets mixing register sizes")
    args = parser.parse_args()

    return args
