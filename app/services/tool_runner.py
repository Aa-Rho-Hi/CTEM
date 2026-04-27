import asyncio
import ipaddress
import json
import logging
import re
import shutil
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# Block all shell metacharacters in user-supplied free-text inputs
_SHELL_META_RE = re.compile(r"[;&|`$<>\\()\[\]{}\n\r\"]")

TIMEOUT_SECONDS = 60


@dataclass
class ToolResult:
    raw_output: str
    exploitation_confirmed: bool
    confidence: int
    summary: str
    findings: list[dict] = field(default_factory=list)


class ToolRunnerError(RuntimeError):
    pass


class ToolNotAvailableError(ToolRunnerError):
    pass


class ToolRunner:
    # -----------------------------------------------------------------
    # Input validation
    # -----------------------------------------------------------------

    @staticmethod
    def _validate_ip(ip: str) -> str:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            raise ValueError(f"Invalid target IP: {ip!r}")
        return ip

    @staticmethod
    def _sanitize_free_text(value: str, field_name: str = "input") -> str:
        if _SHELL_META_RE.search(value):
            raise ValueError(f"{field_name} contains disallowed characters.")
        return value.strip()

    @staticmethod
    def _tool_available(tool: str) -> bool:
        return shutil.which(tool) is not None

    # -----------------------------------------------------------------
    # Subprocess helper
    # -----------------------------------------------------------------

    @staticmethod
    async def _exec(args: list[str]) -> tuple[int, str, str]:
        """Run a subprocess with a hard timeout. Never uses shell=True."""
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=TIMEOUT_SECONDS
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            raise ToolRunnerError(f"Tool timed out after {TIMEOUT_SECONDS}s")
        return proc.returncode, stdout.decode(errors="replace"), stderr.decode(errors="replace")

    # -----------------------------------------------------------------
    # nmap
    # -----------------------------------------------------------------

    async def _run_nmap(self, target_ip: str, _payload: str) -> ToolResult:
        _, stdout, _ = await self._exec(
            ["nmap", "-oX", "-", "-sV", "--open", "-T4", target_ip]
        )
        return self._parse_nmap_xml(stdout, target_ip)

    @staticmethod
    def _parse_nmap_xml(xml_output: str, target_ip: str) -> ToolResult:
        findings: list[dict] = []
        _SENSITIVE = {
            "ssh", "ftp", "telnet", "rdp", "smb", "vnc",
            "mysql", "mssql", "postgresql", "redis", "mongodb",
            "memcached", "elasticsearch", "cassandra",
        }
        try:
            root = ET.fromstring(xml_output)
            for host in root.findall("host"):
                status = host.find("status")
                if status is None or status.get("state") != "up":
                    continue
                for port_el in host.findall(".//port"):
                    state_el = port_el.find("state")
                    if state_el is None or state_el.get("state") != "open":
                        continue
                    svc = port_el.find("service")
                    findings.append({
                        "port": port_el.get("portid"),
                        "protocol": port_el.get("protocol", "tcp"),
                        "service": svc.get("name", "unknown") if svc is not None else "unknown",
                        "product": svc.get("product", "") if svc is not None else "",
                        "version": svc.get("version", "") if svc is not None else "",
                    })
        except ET.ParseError as exc:
            logger.warning("nmap XML parse error: %s", exc)

        sensitive_exposed = [f for f in findings if f["service"].lower() in _SENSITIVE]
        open_count = len(findings)

        if sensitive_exposed:
            confidence = min(40 + len(sensitive_exposed) * 12, 85)
            summary = (
                f"nmap: {open_count} open port(s) on {target_ip}. "
                f"Sensitive services: {', '.join(f['service'] for f in sensitive_exposed)}."
            )
        elif open_count:
            confidence = 35
            summary = f"nmap: {open_count} open port(s) on {target_ip}. No sensitive services detected."
        else:
            confidence = 10
            summary = f"nmap: No open ports found on {target_ip}."

        return ToolResult(
            raw_output=xml_output,
            exploitation_confirmed=False,
            confidence=confidence,
            summary=summary,
            findings=findings,
        )

    # -----------------------------------------------------------------
    # nikto
    # -----------------------------------------------------------------

    async def _run_nikto(self, target_ip: str, _payload: str) -> ToolResult:
        _, stdout, _ = await self._exec(
            ["nikto", "-h", target_ip, "-Format", "json", "-nointeractive", "-maxtime", "50s"]
        )
        return self._parse_nikto(stdout, target_ip)

    @staticmethod
    def _parse_nikto(output: str, target_ip: str) -> ToolResult:
        findings: list[dict] = []
        try:
            data = json.loads(output)
            for v in data.get("vulnerabilities", []):
                findings.append({"id": v.get("id"), "msg": v.get("msg"), "uri": v.get("uri")})
        except (json.JSONDecodeError, AttributeError):
            for line in output.splitlines():
                line = line.strip()
                if line.startswith("+ "):
                    findings.append({"msg": line[2:]})

        _HIGH_SIGNAL = re.compile(r"xss|sql\s*inject|rce|remote\s*exec|traversal|lfi|rfi", re.I)
        critical = [f for f in findings if _HIGH_SIGNAL.search(str(f))]
        exploitation_confirmed = bool(critical)

        if exploitation_confirmed:
            confidence = min(70 + len(critical) * 5, 92)
            summary = f"nikto: {len(findings)} issue(s) including high-signal findings on {target_ip}."
        elif findings:
            confidence = min(45 + len(findings) * 3, 70)
            summary = f"nikto: {len(findings)} issue(s) found on {target_ip}."
        else:
            confidence = 15
            summary = f"nikto: No issues found on {target_ip}."

        return ToolResult(
            raw_output=output,
            exploitation_confirmed=exploitation_confirmed,
            confidence=confidence,
            summary=summary,
            findings=findings,
        )

    # -----------------------------------------------------------------
    # sqlmap
    # -----------------------------------------------------------------

    async def _run_sqlmap(self, target_ip: str, payload: str) -> ToolResult:
        # payload must be a URL path, e.g. /login?id=1
        path = self._sanitize_free_text(payload, "payload") if payload else "/"
        if not path.startswith("/"):
            path = "/" + path
        target_url = f"http://{target_ip}{path}"
        _, stdout, _ = await self._exec([
            "sqlmap", "-u", target_url,
            "--batch", "--level=1", "--risk=1",
            "--output-dir=/tmp/sqlmap_atlas",
        ])
        return self._parse_sqlmap(stdout, target_ip)

    @staticmethod
    def _parse_sqlmap(output: str, target_ip: str) -> ToolResult:
        injection_confirmed = bool(
            re.search(r"sqlmap identified the following injection", output, re.I)
        )
        findings: list[dict] = []
        for line in output.splitlines():
            if re.search(r"injectable|injection point|parameter .+ is vulnerable", line, re.I):
                findings.append({"detail": line.strip()})

        if injection_confirmed:
            confidence = 90
            summary = f"sqlmap: SQL injection confirmed on {target_ip}."
        elif "tested" in output.lower():
            confidence = 20
            summary = f"sqlmap: No injection found on {target_ip}."
        else:
            confidence = 10
            summary = f"sqlmap: Scan incomplete — target may not be reachable."

        return ToolResult(
            raw_output=output,
            exploitation_confirmed=injection_confirmed,
            confidence=confidence,
            summary=summary,
            findings=findings,
        )

    # -----------------------------------------------------------------
    # hydra
    # -----------------------------------------------------------------

    _HYDRA_ALLOWED_SERVICES = frozenset({"ssh", "ftp", "http-get", "smtp", "pop3", "imap"})
    _HYDRA_WORDLIST_DIR = "/usr/share/wordlists/"

    async def _run_hydra(self, target_ip: str, payload: str) -> ToolResult:
        # payload format: "service:wordlist_path"  e.g. "ssh:/usr/share/wordlists/rockyou.txt"
        service = "ssh"
        wordlist = "/usr/share/wordlists/rockyou.txt"
        if payload and ":" in payload:
            svc, wl = payload.split(":", 1)
            svc = svc.strip()
            wl = wl.strip()
            if svc in self._HYDRA_ALLOWED_SERVICES:
                service = svc
            # Reject path traversal attempts
            if wl.startswith(self._HYDRA_WORDLIST_DIR) and ".." not in wl:
                wordlist = wl

        if not self._tool_available("hydra"):
            raise ToolNotAvailableError("hydra is not installed.")

        _, stdout, _ = await self._exec([
            "hydra", "-L", wordlist, "-P", wordlist,
            target_ip, service, "-t", "4", "-f",
        ])
        return self._parse_hydra(stdout, target_ip)

    @staticmethod
    def _parse_hydra(output: str, target_ip: str) -> ToolResult:
        findings: list[dict] = []
        for line in output.splitlines():
            if re.search(r"\[.+\]\s+host:.+login:.+password:", line, re.I):
                findings.append({"credential": line.strip()})

        exploitation_confirmed = bool(findings)
        if exploitation_confirmed:
            confidence = 95
            summary = f"hydra: {len(findings)} valid credential(s) found on {target_ip}."
        else:
            confidence = 10
            summary = f"hydra: No valid credentials found on {target_ip}."

        return ToolResult(
            raw_output=output,
            exploitation_confirmed=exploitation_confirmed,
            confidence=confidence,
            summary=summary,
            findings=findings,
        )

    # -----------------------------------------------------------------
    # metasploit  (pymetasploit3 + msfrpcd)
    # -----------------------------------------------------------------

    # Only allow valid Metasploit module paths: word chars, slashes, hyphens
    _MSF_MODULE_RE = re.compile(r"^[a-z0-9/_-]+$", re.I)
    # How long to wait for a module to finish executing before reading output
    _MSF_POLL_INTERVAL = 2.0
    _MSF_MAX_POLLS = 25  # 25 * 2s = 50s max wait

    async def _run_metasploit(self, target_ip: str, payload: str) -> ToolResult:
        """
        Requires msfrpcd running:
            msfrpcd -P atlas_msf_pass -p 55553 -S  (no SSL for local use)
        Env vars (optional):
            MSF_RPC_HOST  (default: 127.0.0.1)
            MSF_RPC_PORT  (default: 55553)
            MSF_RPC_PASS  (default: atlas_msf_pass)
        payload format: Metasploit module path, e.g. "auxiliary/scanner/portscan/tcp"
        """
        import os
        try:
            from pymetasploit3.msfrpc import MsfRpcClient  # type: ignore
        except ImportError:
            raise ToolNotAvailableError(
                "pymetasploit3 is not installed. Run: pip install pymetasploit3"
            )

        module_path = payload.strip() if payload else "auxiliary/scanner/portscan/tcp"
        if not self._MSF_MODULE_RE.match(module_path):
            raise ValueError(f"Invalid Metasploit module path: {module_path!r}")

        host = os.environ.get("MSF_RPC_HOST", "127.0.0.1")
        port = int(os.environ.get("MSF_RPC_PORT", "55553"))
        password = os.environ.get("MSF_RPC_PASS", "atlas_msf_pass")

        loop = asyncio.get_event_loop()

        def _connect_and_run() -> str:
            client = MsfRpcClient(password, server=host, port=port, ssl=False)
            console = client.consoles.console()
            console.write(f"use {module_path}\n")
            console.write(f"set RHOSTS {target_ip}\n")
            console.write("run -j\n")  # -j runs as a background job

            output_parts: list[str] = []
            for _ in range(self._MSF_MAX_POLLS):
                import time
                time.sleep(self._MSF_POLL_INTERVAL)
                chunk = console.read()
                data = chunk.get("data", "")
                if data:
                    output_parts.append(data)
                # Stop polling once the prompt returns (module finished)
                if chunk.get("prompt", "").endswith("> "):
                    break

            # Collect any open sessions
            sessions = client.sessions.list
            if sessions:
                output_parts.append(f"\n[SESSIONS] {len(sessions)} active session(s) opened.")

            return "".join(output_parts)

        try:
            output = await loop.run_in_executor(None, _connect_and_run)
        except Exception as exc:
            raise ToolRunnerError(f"Metasploit RPC error: {exc}") from exc

        session_opened = bool(
            re.search(r"(Meterpreter|Command shell|session \d+ opened)", output, re.I)
        )
        confidence = 95 if session_opened else 25
        summary = (
            f"metasploit ({module_path}): Session opened on {target_ip}."
            if session_opened
            else f"metasploit ({module_path}): No session established on {target_ip}."
        )
        return ToolResult(
            raw_output=output,
            exploitation_confirmed=session_opened,
            confidence=confidence,
            summary=summary,
        )

    # -----------------------------------------------------------------
    # OWASP ZAP  (REST API — runs via Docker)
    # -----------------------------------------------------------------

    async def _run_burp_suite(self, target_ip: str, _payload: str) -> ToolResult:
        """
        Uses OWASP ZAP REST API (zaproxy/zap-stable Docker image).
        Start ZAP:
            docker run -d --name zap -p 8080:8080 zaproxy/zap-stable \\
              zap.sh -daemon -host 0.0.0.0 -port 8080 \\
              -config api.disablekey=true \\
              -config "api.addrs.addr.name=.*" \\
              -config api.addrs.addr.regex=true

        Env vars (optional):
            ZAP_API_URL  (default: http://localhost:8080)
        """
        import os
        import httpx

        base_url = os.environ.get("ZAP_API_URL", "http://localhost:8080").rstrip("/")
        target_url = f"http://{target_ip}"

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                # 1. Verify ZAP is reachable
                try:
                    health = await client.get(f"{base_url}/JSON/core/view/version/")
                    health.raise_for_status()
                except Exception as exc:
                    raise ToolNotAvailableError(
                        f"ZAP API not reachable at {base_url}. "
                        "Start with: docker run -d --name zap -p 8080:8080 zaproxy/zap-stable "
                        'zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.disablekey=true '
                        '-config "api.addrs.addr.name=.*" -config api.addrs.addr.regex=true'
                    ) from exc

                # 2. Force-access the URL so ZAP adds it to the Sites tree
                await client.get(
                    f"{base_url}/JSON/core/action/accessUrl/",
                    params={"url": target_url, "followRedirects": "true"},
                )

                # 3. Spider the target to discover content
                spider_resp = await client.get(
                    f"{base_url}/JSON/spider/action/scan/",
                    params={"url": target_url, "recurse": "true", "maxChildren": "5"},
                )
                spider_resp.raise_for_status()
                spider_id = spider_resp.json().get("scan", "0")

                # 4. Wait for spider to finish (max 30s)
                for _ in range(15):
                    await asyncio.sleep(2)
                    prog = await client.get(
                        f"{base_url}/JSON/spider/view/status/",
                        params={"scanId": spider_id},
                    )
                    if int(prog.json().get("status", 0)) >= 100:
                        break

                # 5. Run active scan — only proceed if URL is in Sites tree
                scan_resp = await client.get(
                    f"{base_url}/JSON/ascan/action/scan/",
                    params={"url": target_url, "recurse": "true", "inScopeOnly": "false"},
                )
                if scan_resp.status_code == 400:
                    # Target unreachable — fall back to passive alerts only
                    scan_id = None
                else:
                    scan_resp.raise_for_status()
                    scan_id = scan_resp.json().get("scan", "0")

                # 6. Poll until active scan completes (max remaining TIMEOUT)
                if scan_id is not None:
                    deadline = asyncio.get_event_loop().time() + TIMEOUT_SECONDS
                    while asyncio.get_event_loop().time() < deadline:
                        await asyncio.sleep(5)
                        status_resp = await client.get(
                            f"{base_url}/JSON/ascan/view/status/",
                            params={"scanId": scan_id},
                        )
                        pct = int(status_resp.json().get("status", 0))
                        logger.debug("zap active scan progress: %d%%", pct)
                        if pct >= 100:
                            break

                # 7. Fetch alerts for this target
                alerts_resp = await client.get(
                    f"{base_url}/JSON/core/view/alerts/",
                    params={"baseurl": target_url},
                )
                alerts_resp.raise_for_status()
                alerts = alerts_resp.json().get("alerts", [])

        except ToolNotAvailableError:
            raise
        except Exception as exc:
            raise ToolRunnerError(f"ZAP API error: {exc}") from exc

        # ZAP risk levels: 3=High, 2=Medium, 1=Low, 0=Informational
        high_alerts = [a for a in alerts if int(a.get("risk", 0)) >= 2]
        exploitation_confirmed = any(int(a.get("risk", 0)) == 3 for a in alerts)
        confidence = min(50 + len(high_alerts) * 10, 90) if high_alerts else (15 if not alerts else 30)
        summary = (
            f"zap: {len(alerts)} alert(s) on {target_ip}"
            + (f", {len(high_alerts)} Medium/High risk." if high_alerts else ".")
        )
        findings = [
            {
                "name": a.get("alert"),
                "risk": a.get("riskdesc"),
                "confidence": a.get("confidence"),
                "url": a.get("url"),
                "solution": a.get("solution"),
            }
            for a in alerts
        ]
        return ToolResult(
            raw_output=json.dumps(alerts, indent=2),
            exploitation_confirmed=exploitation_confirmed,
            confidence=confidence,
            summary=summary,
            findings=findings,
        )

    # -----------------------------------------------------------------
    # Dispatch table + public entry point
    # -----------------------------------------------------------------

    _DISPATCH: dict = {}  # populated after class definition

    async def run(self, tool: str, target_ip: str, payload: str, technique: str) -> ToolResult:
        self._validate_ip(target_ip)

        runner_fn = self._DISPATCH.get(tool)
        if runner_fn is None:
            raise ToolRunnerError(f"No runner implemented for tool: {tool!r}")

        # Check binary availability for CLI tools (API-based tools handle it internally)
        _cli_tools = {"nmap", "nikto", "sqlmap", "hydra"}
        if tool in _cli_tools and not self._tool_available(tool):
            raise ToolNotAvailableError(
                f"Tool '{tool}' is not installed or not on PATH."
            )

        logger.info("tool_runner.start tool=%s target=%s technique=%s", tool, target_ip, technique)
        try:
            result = await runner_fn(self, target_ip, payload)
        except (ToolRunnerError, ToolNotAvailableError):
            raise
        except Exception as exc:
            logger.exception("tool_runner.error tool=%s", tool)
            raise ToolRunnerError(f"Unexpected error running {tool}: {exc}") from exc

        logger.info(
            "tool_runner.done tool=%s confidence=%d exploitation=%s",
            tool, result.confidence, result.exploitation_confirmed,
        )
        return result


ToolRunner._DISPATCH = {
    "nmap": ToolRunner._run_nmap,
    "nikto": ToolRunner._run_nikto,
    "sqlmap": ToolRunner._run_sqlmap,
    "hydra": ToolRunner._run_hydra,
    "metasploit": ToolRunner._run_metasploit,
    "burp_suite": ToolRunner._run_burp_suite,
    "burpsuite": ToolRunner._run_burp_suite,
}
