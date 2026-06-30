# Sphinx configuration for gemstone_utils documentation.
# Build from repo root:
#   sphinx-build -c docs/sphinx_config docs docs/_build/html
# Or: make -C docs/sphinx_config html

from __future__ import annotations

import os
import sys
from datetime import datetime

_conf_dir = os.path.dirname(os.path.abspath(__file__))
_doc_root = os.path.abspath(os.path.join(_conf_dir, ".."))
_repo_root = os.path.abspath(os.path.join(_doc_root, ".."))

sys.path.insert(0, _repo_root)

# -- Project metadata ---------------------------------------------------------

project = "gemstone_utils"
author = "Gemstone Software"
copyright = f"{datetime.now().year}, {author}"

try:
    from importlib.metadata import version as pkg_version

    release = pkg_version("gemstone_utils")
except Exception:
    release = "0.0.0"
version = release

# -- General ------------------------------------------------------------------

extensions = [
    "myst_parser",
    "sphinx.ext.autodoc",
    "sphinx.ext.autosummary",
    "sphinx.ext.napoleon",
    "sphinx.ext.viewcode",
    "sphinx.ext.intersphinx",
    "sphinx_design",
    "sphinx_copybutton",
    "sphinxcontrib.mermaid",
]

root_doc = "index"
source_suffix = {
    ".rst": "restructuredtext",
    ".md": "markdown",
}
language = "en"

templates_path = []
exclude_patterns = [
    "_build",
    "sphinx_config/_build",
    "Thumbs.db",
    ".DS_Store",
]

pygments_style = "sphinx"
highlight_language = "python"

myst_heading_anchors = 3
myst_enable_extensions = ["colon_fence", "deflist"]

sphinx_design_tabs_dynamic = False

# -- Autodoc ------------------------------------------------------------------

napoleon_google_docstring = True
napoleon_numpy_docstring = False
napoleon_use_ivar = True
autoclass_content = "class"
autodoc_default_options = {
    "members": True,
    "undoc-members": False,
    "show-inheritance": True,
}
autodoc_typehints = "description"

intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
    "sqlalchemy": ("https://docs.sqlalchemy.org/en/20/", None),
}

# -- HTML (Furo) --------------------------------------------------------------

html_theme = "furo"
html_title = project
html_short_title = "gemstone_utils"
html_static_path = ["_static"]
html_baseurl = "https://gemstone-software-dev.github.io/gemstone_utils/"

html_theme_options = {
    "light_logo": "gemstone_software_logo_full_cropped.png",
    "dark_logo": "gemstone_software_logo_full_cropped.png",
    "light_css_variables": {
        "font-stack": '"Open Sans", ui-sans-serif, system-ui, sans-serif',
        "font-stack--monospace": '"Source Code Pro", ui-monospace, monospace',
        "color-gemstone-heading-border": "#6D28D9",
        "color-sidebar-background": "#f3eef8",
        "color-table-header-background": "var(--color-sidebar-background)",
        "color-code-background": "#f0edf4",
        "color-gemstone-target-accent": "#7C3AED",
    },
    "dark_css_variables": {
        "font-stack": '"Open Sans", ui-sans-serif, system-ui, sans-serif',
        "font-stack--monospace": '"Source Code Pro", ui-monospace, monospace',
        "color-gemstone-heading-border": "#A78BFA",
        "color-sidebar-background": "#150d1f",
        "color-table-header-background": "#1f1530",
        "color-gemstone-target-accent": "#C4B5FD",
    },
}

# -- Plain text ---------------------------------------------------------------

text_newlines = "unix"

# -- Logo asset ---------------------------------------------------------------

_LOGO_SIZE = 128
_LOGO_NAME = "gemstone_software_logo_full_cropped.png"
_LOGO_SRC = os.path.join(_doc_root, "static", _LOGO_NAME)
_LOGO_DST = os.path.join(_conf_dir, "_static", _LOGO_NAME)


def _resize_logo(src: str, dst: str, size: int) -> None:
    """Write a square logo PNG; use Pillow when available."""
    try:
        from PIL import Image
    except ImportError:
        import shutil

        shutil.copy2(src, dst)
        return

    with Image.open(src) as img:
        img.convert("RGBA").resize((size, size), Image.Resampling.LANCZOS).save(
            dst, format="PNG"
        )


def _ensure_logo_asset() -> None:
    if not os.path.isfile(_LOGO_SRC):
        raise FileNotFoundError(
            f"Logo source not found: {_LOGO_SRC}. "
            "Add docs/static/gemstone_software_logo_full_cropped.png to the repository."
        )
    os.makedirs(os.path.dirname(_LOGO_DST), exist_ok=True)
    _resize_logo(_LOGO_SRC, _LOGO_DST, _LOGO_SIZE)


def _on_builder_inited(app) -> None:
    if app.builder.format != "html":
        return
    _ensure_logo_asset()
    app.add_css_file("custom.css")


def setup(app):
    _ensure_logo_asset()
    app.connect("builder-inited", _on_builder_inited)
    return {
        "parallel_read_safe": True,
        "parallel_write_safe": True,
    }
