"""cpgvd: CPG-based, context-aware vulnerability detector.

Pipeline: clone a repo -> build a Code Property Graph with Joern ->
walk the CPG to assemble call-graph/data-flow context around candidate
sinks -> ask Claude to judge whether that context constitutes a real,
exploitable vulnerability -> emit a report.
"""

__version__ = "0.1.0"
