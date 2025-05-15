from dataclasses import dataclass, field

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.padding import Padding


@dataclass
class CLIConfig:
    title: str = "Chainsmoker"
    console: Console = field(default_factory=Console)
    border_style: str = "cyan"
    padding: tuple = (1, 2)
    title_align: str = "left"
    error: str = "bold red"
    success: str = "bold green"
    header: str = "bold white"
    indent = 4


class CLIManager:
    def __init__(self, config: CLIConfig | None = None):
        self.config = config if config else CLIConfig()

    def print(
        self,
        message: str,
        style: str = "",
        indent: int | None = None,
    ):
        if indent is None:
            indent = self.config.indent
        if style:
            self.config.console.print(message, style=style)
        else:
            self.config.console.print(Padding(message, (0, 0, 0, indent)))


if __name__ == "__main__":
    console = CLIManager(CLIConfig())
    console.print("Hello, World!")
