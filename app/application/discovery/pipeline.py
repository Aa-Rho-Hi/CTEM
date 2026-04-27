from dataclasses import dataclass


class UnsupportedActiveScanToolError(RuntimeError):
    pass


@dataclass(slots=True)
class ScanPayloadBatch:
    payload_records: list[dict]
    extra: dict[str, object]


class ActiveScanPayloadUseCase:
    def __init__(
        self,
        *,
        run_nmap_scan,
        parse_nmap_xml,
        run_nessus_scan,
        run_qualys_scan,
        run_openvas_scan,
        run_snyk_scan,
        run_checkmarx_scan,
        run_sonarqube_scan,
        run_rapid7_scan,
        run_veracode_scan,
        run_burp_suite_scan,
    ):
        self.run_nmap_scan = run_nmap_scan
        self.parse_nmap_xml = parse_nmap_xml
        self.run_nessus_scan = run_nessus_scan
        self.run_qualys_scan = run_qualys_scan
        self.run_openvas_scan = run_openvas_scan
        self.run_snyk_scan = run_snyk_scan
        self.run_checkmarx_scan = run_checkmarx_scan
        self.run_sonarqube_scan = run_sonarqube_scan
        self.run_rapid7_scan = run_rapid7_scan
        self.run_veracode_scan = run_veracode_scan
        self.run_burp_suite_scan = run_burp_suite_scan

    async def execute(self, *, scan) -> ScanPayloadBatch:
        targets = scan.metadata_json.get("targets", [])
        options = scan.metadata_json.get("options", {})

        if scan.source_tool == "nmap":
            xml_output = self.run_nmap_scan(targets, options)
            return ScanPayloadBatch(
                payload_records=self.parse_nmap_xml(xml_output),
                extra={"raw_output_bytes": len(xml_output)},
            )
        if scan.source_tool == "nessus":
            return ScanPayloadBatch(payload_records=await self.run_nessus_scan(targets, options), extra={})
        if scan.source_tool == "qualys":
            return ScanPayloadBatch(payload_records=await self.run_qualys_scan(targets, options), extra={})
        if scan.source_tool == "openvas":
            return ScanPayloadBatch(payload_records=await self.run_openvas_scan(targets, options), extra={})
        if scan.source_tool == "snyk":
            return ScanPayloadBatch(payload_records=await self.run_snyk_scan(targets, options), extra={})
        if scan.source_tool == "checkmarx":
            return ScanPayloadBatch(payload_records=await self.run_checkmarx_scan(targets, options), extra={})
        if scan.source_tool == "sonarqube":
            return ScanPayloadBatch(payload_records=await self.run_sonarqube_scan(targets, options), extra={})
        if scan.source_tool == "rapid7":
            return ScanPayloadBatch(payload_records=await self.run_rapid7_scan(targets, options), extra={})
        if scan.source_tool == "veracode":
            return ScanPayloadBatch(payload_records=await self.run_veracode_scan(targets, options), extra={})
        if scan.source_tool == "burp_suite":
            return ScanPayloadBatch(payload_records=await self.run_burp_suite_scan(targets, options), extra={})
        raise UnsupportedActiveScanToolError(
            f"Unsupported source_tool '{scan.source_tool}'. "
            "Supported active scan tools: nmap, snyk, nessus, qualys, checkmarx, sonarqube, rapid7, veracode, burp_suite."
        )


class UploadedScanPayloadUseCase:
    def __init__(self, *, coerce_payload_records):
        self.coerce_payload_records = coerce_payload_records

    async def execute(self, *, scan, payload: str = "") -> ScanPayloadBatch:
        content = scan.metadata_json.get("raw_content") if scan.metadata_json else None
        if content:
            payload = content
        if not payload:
            raise ValueError(f"Scan {scan.id} has no content to process.")
        records = self.coerce_payload_records(payload, scan.source_tool)
        return ScanPayloadBatch(payload_records=records, extra={"ingested_bytes": len(payload)})

