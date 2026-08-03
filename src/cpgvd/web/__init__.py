"""Web console: one page over cpgvd's scan reports and benchmark runs."""

from .server import ArtifactStore, build_app, serve

__all__ = ["ArtifactStore", "build_app", "serve"]
