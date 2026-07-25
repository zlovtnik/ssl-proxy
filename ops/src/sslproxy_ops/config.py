from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import AliasChoices, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from sslproxy_ops.paths import repo_root

ProfileMode = Literal["iphone", "linux-shim", "linux-direct", "mac"]
DeploymentTarget = Literal["compose", "kubernetes"]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=None, extra="ignore")

    service_name: str = Field(default="ssl-proxy", validation_alias="UP_READY_SERVICE_NAME")
    frontdoor_service_name: str = Field(
        default="wg-udp-frontdoor", validation_alias="UP_READY_FRONTDOOR_SERVICE_NAME"
    )
    stack_health_services: str = Field(
        default="redpanda postgres java-coordinator ssl-proxy wg-udp-frontdoor",
        validation_alias="UP_READY_STACK_HEALTH_SERVICES",
    )
    memory_file: Path = Field(
        default_factory=lambda: repo_root() / "ops-memory.md",
        validation_alias="UP_READY_MEMORY_FILE",
    )
    profile_mode: ProfileMode | None = Field(default=None, validation_alias="PROFILE_MODE")
    server_ip: str = Field(default="192.168.1.221", validation_alias="SERVER_IP")
    client_ip: str = Field(default="192.168.1.68", validation_alias="CLIENT_IP")
    wg_peers: str = Field(
        default="peer1,peer2", validation_alias=AliasChoices("WG_PEERS", "ROTATOR_PEERS")
    )
    health_timeout_secs: int = Field(default=120, validation_alias="UP_READY_HEALTH_TIMEOUT_SECS")
    check_retry_secs: int = Field(default=15, validation_alias="UP_READY_CHECK_RETRY_SECS")
    log_tail_lines: int = Field(default=200, validation_alias="UP_READY_LOG_TAIL_LINES")
    qr_type: str = Field(default="ansiutf8", validation_alias="UP_READY_QR_TYPE")
    qr_margin: int = Field(default=0, validation_alias="UP_READY_QR_MARGIN")
    credential_handoff_file: Path = Field(
        default_factory=lambda: repo_root() / "secrets" / "up-ready-credentials.txt",
        validation_alias="UP_READY_CREDENTIAL_HANDOFF_FILE",
    )
    skip_registry_preflight: bool = Field(
        default=False, validation_alias="UP_READY_SKIP_REGISTRY_PREFLIGHT"
    )
    deployment_target: DeploymentTarget = Field(
        default="kubernetes", validation_alias="UP_READY_DEPLOYMENT_TARGET"
    )
    build_registry_images: bool = Field(
        default=True, validation_alias="UP_READY_BUILD_REGISTRY_IMAGES"
    )
    mirror_registry_images: bool = Field(
        default=True, validation_alias="UP_READY_MIRROR_REGISTRY_IMAGES"
    )
    kube_context: str = Field(default="", validation_alias="UP_READY_KUBE_CONTEXT")
    kube_namespace: str = Field(default="default", validation_alias="UP_READY_KUBE_NAMESPACE")
    helm_release: str = Field(default="ssl-proxy", validation_alias="UP_READY_HELM_RELEASE")
    helm_timeout: str = Field(default="30m", validation_alias="UP_READY_HELM_TIMEOUT")
    kube_registry_probe_timeout: str = Field(
        default="45s", validation_alias="UP_READY_KUBE_REGISTRY_PROBE_TIMEOUT"
    )
    rollout_status_timeout: str = Field(
        default="10m", validation_alias="UP_READY_ROLLOUT_STATUS_TIMEOUT"
    )

    registry: str | None = Field(default=None, validation_alias="REGISTRY")
    registry_plain_http: str = Field(default="auto", validation_alias="REGISTRY_PLAIN_HTTP")
    image_tag: str | None = Field(default=None, validation_alias="IMAGE_TAG")
    schema_migrator_public_hostname: str | None = Field(
        default=None, validation_alias="SCHEMA_MIGRATOR_PUBLIC_HOSTNAME"
    )
    atheros_search_embedding_backend: str | None = Field(
        default=None, validation_alias="ATHSEARCH_EMBEDDING_BACKEND"
    )
    acme_email: str | None = Field(default=None, validation_alias="ACME_EMAIL")
    wg_port: int = Field(default=443, ge=1, le=65535, validation_alias="WG_PORT")
    wg_internal_port: int = Field(
        default=51820, ge=1, le=65535, validation_alias="WG_INTERNAL_PORT"
    )
    wg_obfuscation_enabled: bool = Field(
        default=False, validation_alias="WG_OBFUSCATION_ENABLED"
    )

    sync_scan_topic: str = Field(default="sync.scan.request", validation_alias="SYNC_SCAN_TOPIC")
    sync_scan_consumer: str = Field(
        default="octopus-scan", validation_alias="SYNC_SCAN_CONSUMER"
    )
    sync_redpanda_bootstrap_servers: str = Field(
        default="redpanda:9092", validation_alias="SYNC_REDPANDA_BOOTSTRAP_SERVERS"
    )
    compose_project_name: str = Field(default="ssl-proxy", validation_alias="COMPOSE_PROJECT_NAME")
    redpanda_image: str = Field(
        default="redpandadata/redpanda:latest", validation_alias="REDPANDA_IMAGE"
    )
    database_url: str | None = Field(default=None, validation_alias="DATABASE_URL")
    migration_mode: str = Field(default="deploy", validation_alias="UP_READY_MIGRATION_MODE")

    @field_validator("migration_mode")
    @classmethod
    def migration_mode_allowed(cls, value: str) -> str:
        allowed = {"deploy", "migrate"}
        if value not in allowed:
            raise ValueError("must be one of deploy, migrate")
        return value

    @field_validator("stack_health_services")
    @classmethod
    def stack_services_must_not_be_empty(cls, value: str) -> str:
        if not value.split():
            raise ValueError("must list at least one service")
        return value

    @field_validator("registry_plain_http")
    @classmethod
    def registry_plain_http_allowed(cls, value: str) -> str:
        allowed = {"auto", "1", "0", "true", "false", "yes", "no"}
        if value not in allowed:
            raise ValueError("must be one of auto, 1, 0, true, false, yes, no")
        return value

    @field_validator("schema_migrator_public_hostname")
    @classmethod
    def schema_migrator_hostname_must_not_include_scheme(
        cls, value: str | None
    ) -> str | None:
        if value and "://" in value:
            raise ValueError("must be a hostname without a URL scheme")
        return value

    @property
    def stack_health_service_names(self) -> list[str]:
        return self.stack_health_services.split()
