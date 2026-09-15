"""Unauthenticated XML-RPC client for koji.rockylinux.org."""

from __future__ import annotations

import datetime
import os
import ssl
import xmlrpc.client
from typing import Any, Optional


DEFAULT_HUB = "https://koji.rockylinux.org/kojihub"


class TimeoutTransport(xmlrpc.client.SafeTransport):
    def __init__(self, timeout: float = 30.0):
        super().__init__(context=ssl.create_default_context())
        self._timeout = timeout

    def make_connection(self, host):
        conn = super().make_connection(host)
        conn.timeout = self._timeout
        return conn


def _as_datetime(value: Any) -> Optional[datetime.datetime]:
    if value is None:
        return None
    if isinstance(value, datetime.datetime):
        dt = value
        if dt.tzinfo is None:
            return dt.replace(tzinfo=datetime.timezone.utc)
        return dt.astimezone(datetime.timezone.utc)
    if isinstance(value, xmlrpc.client.DateTime):
        raw = value.value
        try:
            dt = datetime.datetime.strptime(raw, "%Y%m%dT%H:%M:%S")
        except ValueError:
            try:
                dt = datetime.datetime.fromisoformat(raw.replace("Z", "+00:00"))
            except ValueError:
                return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        return dt.astimezone(datetime.timezone.utc)
    if isinstance(value, str) and value:
        try:
            dt = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        return dt.astimezone(datetime.timezone.utc)
    return None


class KojiClient:
    def __init__(self, hub: Optional[str] = None, timeout: float = 30.0):
        self.hub = hub or os.environ.get("KOJI_HUB", DEFAULT_HUB)
        self._proxy = xmlrpc.client.ServerProxy(
            self.hub,
            transport=TimeoutTransport(timeout=timeout),
            allow_none=True,
        )

    def get_build(self, nvr_or_id: Any) -> Optional[dict]:
        try:
            build = self._proxy.getBuild(nvr_or_id)
        except xmlrpc.client.Fault:
            return None
        if not build:
            return None
        return dict(build)

    def get_rpm(self, nvra: str) -> Optional[dict]:
        try:
            rpm = self._proxy.getRPM(nvra)
        except xmlrpc.client.Fault:
            return None
        if not rpm:
            return None
        return dict(rpm)

    def completion_for_nvr(self, nvr: str) -> Optional[datetime.datetime]:
        build = self.get_build(nvr)
        if not build:
            return None
        return _as_datetime(build.get("completion_time"))

    def completion_for_rpm(self, nvra: str) -> Optional[datetime.datetime]:
        rpm = self.get_rpm(nvra)
        if not rpm:
            return None
        build_id = rpm.get("build_id")
        if not build_id:
            return None
        build = self.get_build(build_id)
        if not build:
            return None
        return _as_datetime(build.get("completion_time"))
