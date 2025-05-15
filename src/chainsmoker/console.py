from dataclasses import dataclass, field
from typing import Optional, Union, Tuple, Literal
from rich.text import Text
from rich.console import Console, JustifyMethod
from rich.panel import Panel
from rich.padding import Padding
from rich.table import Table


@dataclass
class Style:
    title: str = "bold white"
    error: str = "bold red"
    success: str = "bold green"
    header: str = "bold white"
    warning: str = "bold yellow"
    default: str = "white"


@dataclass
class CLIConfig:
    console: Console = field(default_factory=Console)
    padding: Tuple[int, int] = (1, 2)
    title_align: Literal["left", "center", "right"] = "left"
    style: Style = field(default_factory=Style)
    indent: int = 2


class CLIManager:
    def __init__(self, config: Optional[CLIConfig] = None):
        self.config = config or CLIConfig()
        self.styles = self.config.style

    def _resolve_style(self, style: Optional[str], default_style_name: Optional[str] = None) -> str:
        if style in vars(self.config.style):
            return getattr(self.config.style, style)
        elif style is None and default_style_name:
            return getattr(self.config.style, default_style_name)
        elif style is None:
            return self.config.style.default
        else:
            return style

    def print(
        self,
        text: Union[str, Text],
        style: Optional[str] = None,
        indent: Optional[int] = None,
    ):
        indent = indent if indent is not None else self.config.indent
        resolved_style = self._resolve_style(style)

        if isinstance(text, str):
            if "[" in text and "]" in text:
                text = Text.from_markup(text)
            else:
                text = Text(text, style=resolved_style)

        style_param = None if isinstance(text, Text) else resolved_style

        self.config.console.print(Padding(text, (0, 0, 0, indent)), style=style_param)

    def create_panel(
        self,
        message: Union[str, Text],
        title: str,
        style: Optional[str] = None,
    ) -> Panel:
        border_style = self._resolve_style(style, "title")

        if isinstance(message, str):
            if "[" in message and "]" in message:
                message = Text.from_markup(message)
            else:
                message = Text(message, style=self._resolve_style(None))

        return Panel(
            message,
            title=title,
            border_style=border_style,
            expand=True,
            title_align=self.config.title_align,
            padding=self.config.padding,
        )

    def create_table(
        self,
        title: str,
        columns: list[tuple[str, str, JustifyMethod]],
        header_style: Optional[str] = None,
        border_style: Optional[str] = None,
        title_style: Optional[str] = None,
        expand: bool = False,
    ) -> Table:
        resolved_header = self._resolve_style(header_style, "header")
        resolved_border = self._resolve_style(border_style, "title")
        resolved_title = self._resolve_style(title_style, "title")

        table = Table(
            title=title,
            show_header=True,
            header_style=resolved_header,
            border_style=resolved_border,
            title_style=resolved_title,
            padding=(0, 2),
            expand=expand,
        )

        for name, style, justify in columns:
            resolved_column_style = self._resolve_style(style)
            table.add_column(name, style=resolved_column_style, justify=justify)

        return table


if __name__ == "__main__":
    cli = CLIManager()
    cli.print("test style", style="title")
    cli.print("test error", style="error")
    cli.print("test success", style="success")
    cli.print("test header", style="header")
    cli.print("test warning", style="warning")
    cli.print("test default")
    cli.print("test default with indent", indent=4)
    cli.print("Hello, World!", style="bold blue")
    cli.print("[bold red]Formatted[/bold red] text")
    error_panel = cli.create_panel("Operation failed", "Error", style="error")
    success_panel = cli.create_panel("Operation successfully failed", "Success", style="success")
    markup_panel = cli.create_panel("[bold]Important[/bold] details", "Alert")

    cli.config.console.print(error_panel)
    cli.config.console.print(success_panel)
    cli.config.console.print(markup_panel)

    table = cli.create_table(
        "User Information",
        [
            ("Name", "default", "left"),
            ("Email", "default", "left"),
            ("Status", "default", "center"),
        ],
    )
    table.add_row("John Doe", "john@example.com", "[green]Active[/green]")
    table.add_row("Jane Smith", "jane@example.com", "[red]Inactive[/red]")

    cli.config.console.print(table)

    table = cli.create_table(
        "Error Report",
        [
            ("Error Type", "error", "left"),
            ("Timestamp", "default", "right"),
            ("Status", "success", "center"),
        ],
        header_style="error",
        border_style="bold blue",
    )

    table.add_row("John Doe", "john@example.com", "[green]Active[/green]")
    table.add_row("Jane Smith", "jane@example.com", "[red]Inactive[/red]")
    cli.config.console.print(table)
