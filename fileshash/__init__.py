try:
    from fileshash import FilesHash, SUPPORTED_ALGORITHMS
except ImportError:
    from .fileshash import FilesHash, SUPPORTED_ALGORITHMS

__all__ = ["FilesHash", "SUPPORTED_ALGORITHMS"]
