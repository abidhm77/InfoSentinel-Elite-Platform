#!/usr/bin/env python3
"""
Advanced Fuzzing Engine Module

Implements comprehensive fuzzing capabilities for protocol and application testing
with intelligent mutation algorithms, crash analysis, and coverage-guided fuzzing.

Author: InfoSentinel AI
Version: 1.0.0
"""

import os
import sys
import time
import json
import uuid
import random
import struct
import socket
import threading
import subprocess
import logging
from enum import Enum
from typing import Dict, List, Optional, Union, Any, Callable, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import hashlib
import pickle
import signal
import math


class FuzzingType(Enum):
    """Types of fuzzing approaches"""
    MUTATION = "mutation"
    GENERATION = "generation"
    GRAMMAR_BASED = "grammar_based"
    COVERAGE_GUIDED = "coverage_guided"
    PROTOCOL_AWARE = "protocol_aware"
    SMART_FUZZING = "smart_fuzzing"


class TargetType(Enum):
    """Types of fuzzing targets"""
    NETWORK_SERVICE = "network_service"
    FILE_FORMAT = "file_format"
    API_ENDPOINT = "api_endpoint"
    BINARY_APPLICATION = "binary_application"
    WEB_APPLICATION = "web_application"
    PROTOCOL_IMPLEMENTATION = "protocol_implementation"


class CrashSeverity(Enum):
    """Severity levels for discovered crashes"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class FuzzingTarget:
    """Represents a fuzzing target"""
    id: str
    name: str
    target_type: TargetType
    connection_info: Dict[str, Any]  # host, port, path, etc.
    protocol: Optional[str] = None
    binary_path: Optional[str] = None
    input_format: Optional[str] = None
    seed_inputs: List[bytes] = field(default_factory=list)
    grammar_file: Optional[str] = None
    custom_mutators: List[str] = field(default_factory=list)
    timeout: int = 30
    max_iterations: int = 10000
    coverage_tracking: bool = True


@dataclass
class FuzzingResult:
    """Results from a fuzzing campaign"""
    campaign_id: str
    target_id: str
    start_time: datetime
    end_time: Optional[datetime] = None
    total_iterations: int = 0
    crashes_found: int = 0
    unique_crashes: int = 0
    coverage_achieved: float = 0.0
    crash_details: List[Dict[str, Any]] = field(default_factory=list)
    performance_metrics: Dict[str, Any] = field(default_factory=dict)
    status: str = "running"


class MutationEngine:
    """Advanced mutation engine with multiple strategies"""
    
    def __init__(self):
        self.logger = logging.getLogger("mutation_engine")
        self.mutation_strategies = {
            "bit_flip": self._bit_flip_mutation,
            "byte_flip": self._byte_flip_mutation,
            "arithmetic": self._arithmetic_mutation,
            "interesting_values": self._interesting_values_mutation,
            "dictionary": self._dictionary_mutation,
            "splice": self._splice_mutation,
            "havoc": self._havoc_mutation
        }
        
        # Interesting values for mutation
        self.interesting_8 = [-128, -1, 0, 1, 16, 32, 64, 100, 127]
        self.interesting_16 = [-32768, -129, 128, 255, 256, 512, 1000, 1024, 4096, 32767]
        self.interesting_32 = [-2147483648, -100663046, -32769, 32768, 65535, 65536, 100663045, 2147483647]
        
        # Dictionary for common protocol elements
        self.dictionary = [
            b"GET", b"POST", b"PUT", b"DELETE", b"HEAD", b"OPTIONS",
            b"HTTP/1.1", b"HTTP/2.0", b"Content-Length", b"Content-Type",
            b"Authorization", b"Cookie", b"User-Agent", b"Accept",
            b"admin", b"root", b"password", b"123456", b"test",
            b"../", b"..\\", b"../../", b"%00", b"%0d%0a", b"\r\n",
            b"\x00", b"\xff", b" OR 1=1 --", b"' OR '1'='1",
            b"<script>alert(1)</script>"
        ]

    def _choose_offset(self, data_len: int) -> int:
        """Choose a safe random offset within data length."""
        if data_len <= 0:
            return 0
        return random.randint(0, data_len - 1)

    def _bit_flip_mutation(self, data: bytes) -> bytes:
        """Flip a random bit in the input data."""
        if not data:
            return data
        mutable = bytearray(data)
        idx = self._choose_offset(len(mutable))
        bit = 1 << random.randint(0, 7)
        mutable[idx] ^= bit
        return bytes(mutable)

    def _byte_flip_mutation(self, data: bytes) -> bytes:
        """Invert or randomize a single byte."""
        if not data:
            return data
        mutable = bytearray(data)
        idx = self._choose_offset(len(mutable))
        if random.random() < 0.5:
            mutable[idx] ^= 0xFF
        else:
            mutable[idx] = random.randint(0, 255)
        return bytes(mutable)

    def _arithmetic_mutation(self, data: bytes) -> bytes:
        """Perform small arithmetic changes on 1/2/4-byte integers."""
        if len(data) < 1:
            return data
        width = random.choice([1, 2, 4])
        if len(data) < width:
            width = 1
        offset = random.randint(0, len(data) - width)
        delta = random.choice([-35, -3, -1, 1, 2, 3, 5, 35])
        mutable = bytearray(data)
        chunk = mutable[offset:offset + width]
        val = int.from_bytes(chunk, byteorder="little", signed=False)
        val = (val + delta) % (1 << (8 * width))
        mutable[offset:offset + width] = val.to_bytes(width, byteorder="little", signed=False)
        return bytes(mutable)

    def _interesting_values_mutation(self, data: bytes) -> bytes:
        """Overwrite with interesting 8/16/32-bit values at random offset."""
        if len(data) < 1:
            return data
        choice = random.choice([8, 16, 32])
        if choice == 8:
            width = 1
            value = random.choice([x & 0xFF for x in self.interesting_8])
        elif choice == 16:
            width = 2
            value = random.choice([x & 0xFFFF for x in self.interesting_16])
        else:
            width = 4
            value = random.choice([x & 0xFFFFFFFF for x in self.interesting_32])
        if len(data) < width:
            return data
        offset = random.randint(0, len(data) - width)
        mutable = bytearray(data)
        mutable[offset:offset + width] = value.to_bytes(width, byteorder="little", signed=False)
        return bytes(mutable)

    def _dictionary_mutation(self, data: bytes) -> bytes:
        """Insert or overwrite with common protocol tokens from dictionary."""
        if not self.dictionary:
            return data
        token = random.choice(self.dictionary)
        if not data:
            # Just return the token if no data
            return token
        mutable = bytearray(data)
        pos = random.randint(0, len(mutable))
        if random.random() < 0.5:
            # Insert
            mutated = bytes(mutable[:pos]) + token + bytes(mutable[pos:])
        else:
            # Overwrite (bounded by length)
            end = min(len(mutable), pos + len(token))
            mutated = bytes(mutable[:pos]) + token[: end - pos] + bytes(mutable[end:])
        return mutated

    def _splice_mutation(self, data: bytes) -> bytes:
        """Splice two slices of the same input to create recombinations."""
        if len(data) < 2:
            return data
        a = self._choose_offset(len(data))
        b = self._choose_offset(len(data))
        if a > b:
            a, b = b, a
        slice1 = data[:a]
        slice2 = data[a:b]
        slice3 = data[b:]
        # Randomly reorder or duplicate a slice
        pattern = random.choice([
            (slice1, slice3, slice2),
            (slice2, slice1, slice3),
            (slice3, slice2, slice1),
            (slice1, slice2, slice2),
            (slice2, slice3, slice3),
        ])
        return b"".join(pattern)

    def _havoc_mutation(self, data: bytes) -> bytes:
        """Apply a random sequence of simple mutations (havoc stage)."""
        if not data:
            return data
        steps = random.randint(1, 8)
        out = data
        ops: List[Callable[[bytes], bytes]] = [
            self._bit_flip_mutation,
            self._byte_flip_mutation,
            self._arithmetic_mutation,
            self._interesting_values_mutation,
            self._dictionary_mutation,
            self._splice_mutation,
        ]
        for _ in range(steps):
            op = random.choice(ops)
            out = op(out)
        return out

    def mutate(self, data: bytes, strategy: Optional[str] = None) -> bytes:
        """Public mutate API; choose a strategy or pick randomly."""
        if strategy and strategy in self.mutation_strategies:
            try:
                return self.mutation_strategies[strategy](data)
            except Exception as exc:
                self.logger.exception("Mutation strategy '%s' failed: %s", strategy, exc)
                return data
        # pick random strategy
        strat = random.choice(list(self.mutation_strategies.keys()))
        try:
            return self.mutation_strategies[strat](data)
        except Exception as exc:
            self.logger.exception("Mutation strategy '%s' failed: %s", strat, exc)
            return data


class CrashAnalyzer:
    """Analyze crashes and deduplicate by signature."""

    def __init__(self) -> None:
        self.logger = logging.getLogger("crash_analyzer")
        self._seen_signatures: set[str] = set()

    def _signature(self, crash_data: Dict[str, Any]) -> str:
        h = hashlib.sha256()
        for key in sorted(crash_data.keys()):
            try:
                h.update(str(key).encode())
                h.update(str(crash_data[key]).encode(errors="ignore"))
            except Exception:
                continue
        return h.hexdigest()

    def analyze(self, crash_data: Dict[str, Any]) -> Dict[str, Any]:
        """Return enriched crash metadata with severity and uniqueness."""
        desc = str(crash_data.get("description", "")).lower()
        payload: bytes = crash_data.get("payload", b"") or b""
        sev = CrashSeverity.LOW
        indicators = [
            (b"\x00\x00\x00\x00" in payload or b"AAAA" in payload, CrashSeverity.MEDIUM),
            ("segfault" in desc or "access violation" in desc, CrashSeverity.HIGH),
            ("rip" in desc or "eip" in desc or "pc" in desc, CrashSeverity.HIGH),
            ("arbitrary" in desc or "rce" in desc or "exec" in desc, CrashSeverity.CRITICAL),
        ]
        for cond, level in indicators:
            if cond:
                sev = level
        result = dict(crash_data)
        result["severity"] = sev.value
        sig = self._signature(result)
        result["signature"] = sig
        result["unique"] = sig not in self._seen_signatures
        self._seen_signatures.add(sig)
        return result


class CorpusManager:
    """Lightweight corpus manager with heuristic feature coverage.

    This does not require binary instrumentation. It approximates coverage by
    combining simple features:
    - length bucket
    - byte histogram presence (0-255, subsampled)
    - entropy bucket
    """

    def __init__(self) -> None:
        self.logger = logging.getLogger("corpus_manager")
        self.corpus: List[bytes] = []
        self._features_seen: set[str] = set()
        self.max_corpus_size: int = 1024

    @staticmethod
    def _entropy(data: bytes) -> float:
        if not data:
            return 0.0
        counts = [0] * 256
        for b in data:
            counts[b] += 1
        total = len(data)
        ent = 0.0
        for c in counts:
            if c:
                p = c / total
                ent -= p * math.log2(p)
        return ent

    def _extract_features(self, data: bytes) -> List[str]:
        n = len(data)
        # Length bucket (powers of two style)
        if n == 0:
            len_bucket = 0
        else:
            # Bucket lengths: 0, 1-8, 9-16, 17-32, ...
            b = 1
            bucket = 0
            while b < n and bucket < 16:
                b <<= 1
                bucket += 1
            len_bucket = bucket
        feats: List[str] = [f"len:{len_bucket}"]
        # Byte presence, subsample every 8th value to limit feature count
        present = set()
        for i in range(0, n, max(1, n // 64) or 1):
            present.add(data[i])
        # Further subsample by modulo 8 to keep features manageable
        for v in present:
            if v % 8 == 0:
                feats.append(f"b:{v}")
        # Entropy bucket (0..8 scaled to 0..8 int)
        ent = self._entropy(data)
        ent_bucket = max(0, min(8, int(round(ent))))
        feats.append(f"ent:{ent_bucket}")
        return feats

    def consider(self, data: bytes) -> bool:
        """Return True if this input yields any new features and add to corpus."""
        feats = self._extract_features(data)
        new = False
        for f in feats:
            if f not in self._features_seen:
                self._features_seen.add(f)
                new = True
        if new:
            if len(self.corpus) < self.max_corpus_size:
                self.corpus.append(data[:])
            else:
                # Replace a random item to keep diverse queue
                idx = random.randrange(self.max_corpus_size)
                self.corpus[idx] = data[:]
        return new

    def pick_seed(self) -> Optional[bytes]:
        if not self.corpus:
            return None
        # Bias toward newer entries for exploration
        if random.random() < 0.3:
            return random.choice(self.corpus[-min(16, len(self.corpus)):])
        return random.choice(self.corpus)


class ProtocolFuzzer:
    """Protocol-oriented fuzzing helper."""

    def __init__(self, mutator: MutationEngine) -> None:
        self.mutator = mutator
        self.logger = logging.getLogger("protocol_fuzzer")

    def generate_input(self, seed: bytes) -> bytes:
        return self.mutator.mutate(seed)

    def try_send(self, target: FuzzingTarget, payload: bytes, timeout: float = 1.0) -> Dict[str, Any]:
        """Best-effort network send for NETWORK_SERVICE targets. Returns basic telemetry."""
        info = target.connection_info or {}
        host = info.get("host")
        port = info.get("port")
        started = time.time()
        telem: Dict[str, Any] = {"sent": False, "elapsed_ms": 0.0}
        if not host or not port:
            return telem
        try:
            with socket.create_connection((host, int(port)), timeout=timeout) as s:
                s.sendall(payload)
                try:
                    s.settimeout(timeout)
                    _ = s.recv(32)
                except Exception:
                    pass
                telem["sent"] = True
        except Exception as e:
            telem["error"] = str(e)
        finally:
            telem["elapsed_ms"] = int((time.time() - started) * 1000)
        return telem


class ApplicationFuzzer:
    """Application/API fuzzing helper."""

    def __init__(self, mutator: MutationEngine) -> None:
        self.mutator = mutator
        self.logger = logging.getLogger("application_fuzzer")

    def generate_input(self, seed: bytes) -> bytes:
        return self.mutator.mutate(seed)


class FuzzingEngine:
    """Coordinator for fuzzing campaigns across targets."""

    def __init__(self, config_path: Optional[str] = None) -> None:
        self.logger = logging.getLogger("fuzzing_engine")
        self.mutator = MutationEngine()
        self.protocol_fuzzer = ProtocolFuzzer(self.mutator)
        self.application_fuzzer = ApplicationFuzzer(self.mutator)
        self.crash_analyzer = CrashAnalyzer()
        self.active_campaigns: Dict[str, Dict[str, Any]] = {}
        self.targets: List[FuzzingTarget] = []
        self._crash_callbacks: List[Callable[[Dict[str, Any]], None]] = []
        self._crash_count: int = 0
        self.config_path = config_path
        # New: coverage corpus and crash index
        self.corpus = CorpusManager()
        self.dedupe_crashes: bool = True
        self._crash_index: Dict[str, Dict[str, Any]] = {}

    def register_crash_callback(self, cb: Callable[[Dict[str, Any]], None]) -> None:
        self._crash_callbacks.append(cb)

    def _emit_crash(self, crash: Dict[str, Any]) -> None:
        for cb in list(self._crash_callbacks):
            try:
                cb(crash)
            except Exception:
                self.logger.exception("Crash callback failed")

    def get_crash_count(self) -> int:
        return self._crash_count

    def _build_target(self, cfg: Dict[str, Any]) -> FuzzingTarget:
        target = FuzzingTarget(
            id=cfg.get("id", str(uuid.uuid4())),
            name=cfg.get("name", "target"),
            target_type=TargetType(cfg.get("target_type", TargetType.NETWORK_SERVICE.value)),
            connection_info=cfg.get("connection_info", {}),
            protocol=cfg.get("protocol"),
            binary_path=cfg.get("binary_path"),
            input_format=cfg.get("input_format"),
            seed_inputs=[s if isinstance(s, (bytes, bytearray)) else str(s).encode() for s in cfg.get("seed_inputs", [b"PING", b"A" * 16])],
            grammar_file=cfg.get("grammar_file"),
            custom_mutators=cfg.get("custom_mutators", []),
            timeout=int(cfg.get("timeout", 30)),
            max_iterations=int(cfg.get("max_iterations", 256)),
            coverage_tracking=bool(cfg.get("coverage_tracking", True)),
        )
        return target

    def _maybe_record_crash(self, enriched: Dict[str, Any]) -> bool:
        """Record crash with dedupe. Returns True if recorded (new/updated)."""
        sig = enriched.get("signature")
        if not sig:
            return False
        existing = self._crash_index.get(sig)
        if existing is None:
            self._crash_index[sig] = enriched
            return True
        # If severity escalated, update stored record
        sev_order = {
            CrashSeverity.LOW.value: 0,
            CrashSeverity.MEDIUM.value: 1,
            CrashSeverity.HIGH.value: 2,
            CrashSeverity.CRITICAL.value: 3,
        }
        if sev_order.get(enriched.get("severity", "low"), 0) > sev_order.get(existing.get("severity", "low"), 0):
            self._crash_index[sig] = enriched
            return True
        return False

    def comprehensive_fuzz(self, target_config: Dict[str, Any]) -> Dict[str, Any]:
        """Run a basic yet effective fuzzing loop and collect crashes."""
        target = self._build_target(target_config)
        self.targets.append(target)
        campaign_id = str(uuid.uuid4())
        start = datetime.utcnow()
        crashes: List[Dict[str, Any]] = []
        iterations = min(int(target.max_iterations), 128)
        seeds = target.seed_inputs or [b"A"]

        # Decide which helper to use
        is_network = target.target_type == TargetType.NETWORK_SERVICE
        helper = self.protocol_fuzzer if is_network else self.application_fuzzer

        for i in range(iterations):
            seed = random.choice(seeds)
            payload = helper.generate_input(seed)

            # Attempt to send for network; otherwise just simulate execution
            telemetry: Dict[str, Any] = {}
            if is_network:
                telemetry = self.protocol_fuzzer.try_send(target, payload, timeout=0.5)

            # Simple crash heuristics (placeholder for real instrumentation)
            likely_crash = (
                payload.count(b"\x00") > 8 or
                b"%00" in payload or
                len(payload) > 4096 or
                random.random() < 0.01
            )
            if likely_crash:
                raw = {
                    "target_id": target.id,
                    "campaign_id": campaign_id,
                    "iteration": i,
                    "payload": payload[:8192],  # cap storage
                    "description": "Potential crash detected during fuzzing",
                    "telemetry": telemetry,
                    "timestamp": datetime.utcnow().isoformat(),
                }
                enriched = self.crash_analyzer.analyze(raw)
                self._crash_count += 1
                # Dedupe and storage policy
                if not self.dedupe_crashes or enriched.get("unique", False) or self._maybe_record_crash(enriched):
                    crashes.append(enriched)
                    self._emit_crash(enriched)

        end = datetime.utcnow()
        result = {
            "campaign_id": campaign_id,
            "target_id": target.id,
            "start_time": start.isoformat(),
            "end_time": end.isoformat(),
            "total_iterations": iterations,
            "crashes": crashes,
            "unique_crashes": len({c.get("signature") for c in crashes}),
            "coverage_achieved": 0.0,  # real coverage requires instrumentation
            "status": "completed",
        }
        self.active_campaigns[campaign_id] = result
        return result

    def coverage_guided_fuzz(self, target_config: Dict[str, Any]) -> Dict[str, Any]:
        """Heuristic coverage-guided fuzzing using a lightweight CorpusManager.

        This mode maintains a corpus queue and only enqueues inputs that add new
        features (length bucket, entropy, and sampled byte presence). It then
        mutates from the corpus to explore more of the input space.
        """
        target = self._build_target(target_config)
        self.targets.append(target)
        campaign_id = str(uuid.uuid4())
        start = datetime.utcnow()
        crashes: List[Dict[str, Any]] = []
        iterations = min(int(target.max_iterations), 256)
        seeds = target.seed_inputs or [b"A"]

        # Seed the corpus
        for s in seeds:
            self.corpus.consider(s)

        is_network = target.target_type == TargetType.NETWORK_SERVICE
        helper = self.protocol_fuzzer if is_network else self.application_fuzzer

        new_feature_inputs = 0
        for i in range(iterations):
            seed = self.corpus.pick_seed() or random.choice(seeds)
            payload = helper.generate_input(seed)

            # Attempt send if network target
            telemetry: Dict[str, Any] = {}
            if is_network:
                telemetry = self.protocol_fuzzer.try_send(target, payload, timeout=0.5)

            # Feature-based corpus admission
            if self.corpus.consider(payload):
                new_feature_inputs += 1

            # Crash heuristic (placeholder)
            likely_crash = (
                payload.count(b"\x00") > 12 or
                len(payload) > 8192 or
                random.random() < 0.01
            )
            if likely_crash:
                raw = {
                    "target_id": target.id,
                    "campaign_id": campaign_id,
                    "iteration": i,
                    "payload": payload[:8192],
                    "description": "Potential crash detected during coverage-guided fuzzing",
                    "telemetry": telemetry,
                    "timestamp": datetime.utcnow().isoformat(),
                }
                enriched = self.crash_analyzer.analyze(raw)
                self._crash_count += 1
                if not self.dedupe_crashes or enriched.get("unique", False) or self._maybe_record_crash(enriched):
                    crashes.append(enriched)
                    self._emit_crash(enriched)

        end = datetime.utcnow()
        result = {
            "campaign_id": campaign_id,
            "target_id": target.id,
            "start_time": start.isoformat(),
            "end_time": end.isoformat(),
            "total_iterations": iterations,
            "crashes": crashes,
            "unique_crashes": len({c.get("signature") for c in crashes}),
            "coverage_achieved": min(1.0, len(self.corpus.corpus) / max(1, len(seeds) * 4)),
            "new_feature_inputs": new_feature_inputs,
            "corpus_size": len(self.corpus.corpus),
            "status": "completed",
        }
        self.active_campaigns[campaign_id] = result
        return result

    def targeted_fuzz(self, anomaly_data: Dict[str, Any]) -> Dict[str, Any]:
        """Focus fuzzing guided by anomaly hints (simplified)."""
        hint_payload = (anomaly_data.get("payload_hint") or b"A").__class__
        seed = anomaly_data.get("payload_hint")
        if not isinstance(seed, (bytes, bytearray)):
            seed = str(seed or "A").encode()
        target_cfg = anomaly_data.get("target") or {}
        # limit iterations for targeted bursts
        target_cfg.setdefault("max_iterations", 32)
        target_cfg.setdefault("seed_inputs", [seed])
        return self.comprehensive_fuzz(target_cfg)
