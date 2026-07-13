"""Abstract trustful mutable store interface."""

from abc import ABC, abstractmethod


class TrustfulStore(ABC):
    @abstractmethod
    def publish_identity(self, identifier, public_key, metadata):
        """Publish a public key and optional metadata for an identifier."""

    @abstractmethod
    def resolve_public_key(self, identifier):
        """Resolve identifier to a base64 Ed25519 public key."""

    @abstractmethod
    def resolve_metadata(self, identifier):
        """Resolve identifier to metadata."""
