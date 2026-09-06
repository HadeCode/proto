from datetime import datetime
from typing import Any

import ipaddress
from pydantic import AwareDatetime, BaseModel, Field, field_validator


class Flow(BaseModel):
    timestamp: AwareDatetime

    src_ip: str
    dst_ip: str

    @field_validator("src_ip", "dst_ip")
    @classmethod
    def valid_address(cls, value: str) -> str:
        return str(ipaddress.ip_address(value))

    src_port: int = Field(ge=0, le=65535)
    dst_port: int = Field(ge=0, le=65535)

    protocol: str

    bytes_out: int = Field(ge=0)
    bytes_in: int = Field(ge=0)

    packets_out: int = Field(ge=0)
    packets_in: int = Field(ge=0)

    tcp_flags: str = ""
    context: dict[str, Any] = Field(default_factory=dict)

    # The detector accepts these collector enrichments at the top level too.
    # It normalizes them into ``context`` before analysis.
    dns_metadata: dict[str, Any] | None = None
    tls_metadata: dict[str, Any] | None = None
    quic_metadata: dict[str, Any] | None = None
    destination_reputation: Any | None = None
