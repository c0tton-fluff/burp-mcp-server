package com.burpbridge

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.scanner.AuditConfiguration
import burp.api.montoya.scanner.BuiltInAuditConfiguration
import burp.api.montoya.scanner.audit.Audit
import burp.api.montoya.scanner.audit.issues.AuditIssue
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.concurrent.ConcurrentHashMap

/**
 * Manages audit lifecycle. Stores Audit handles keyed by generated scan_id.
 * Auto-cleans completed scans after 1 hour.
 */
class ScanManager(private val api: MontoyaApi) {

    data class ScanEntry(
        val audit: Audit,
        val target: String,
        val config: String,
        val startedAt: Instant,
        val scanId: String
    )

    private val scans = ConcurrentHashMap<String, ScanEntry>()

    init {
        // Cleanup thread: remove completed scans older than 1 hour
        Thread({
            while (true) {
                try {
                    Thread.sleep(60_000)
                    val cutoff = Instant.now().minusSeconds(3600)
                    scans.entries.removeIf { (_, entry) ->
                        isTerminal(entry) && entry.startedAt.isBefore(cutoff)
                    }
                } catch (_: InterruptedException) {
                    break
                }
            }
        }, "burp-bridge-cleanup").apply {
            isDaemon = true
            start()
        }
    }

    /**
     * Starts a targeted audit. Sends request first, then feeds the
     * HttpRequestResponse into the audit. Returns status DTO immediately.
     */
    fun startScan(req: ScanRequestDto, passive: Boolean): ScanStatusDto {
        val host = req.host.ifBlank { extractHost(req.request) }
        val port = req.port
        val useHttps = req.https

        val httpService = HttpService.httpService(host, port, useHttps)
        val httpRequest = HttpRequest.httpRequest(httpService, req.request)

        // Send request to get a live HttpRequestResponse for the audit
        val httpRequestResponse = api.http().sendRequest(httpRequest)

        // Select audit type
        val builtIn = if (passive) {
            BuiltInAuditConfiguration.LEGACY_PASSIVE_AUDIT_CHECKS
        } else {
            BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS
        }
        val auditConfig = AuditConfiguration.auditConfiguration(builtIn)

        // Start the audit, then feed it the request/response
        val audit = api.scanner().startAudit(auditConfig)
        audit.addRequestResponse(httpRequestResponse)

        val scanId = generateId()
        val target = extractTarget(req.request)
        val configName = if (passive) "passive" else "active"
        val now = Instant.now()

        scans[scanId] = ScanEntry(
            audit = audit,
            target = target,
            config = configName,
            startedAt = now,
            scanId = scanId
        )

        return ScanStatusDto(
            scan_id = scanId,
            status = "running",
            target = target,
            config = configName,
            started_at = now.atOffset(ZoneOffset.UTC)
                .format(DateTimeFormatter.ISO_OFFSET_DATE_TIME)
        )
    }

    /**
     * Returns current status of a scan, or null if not found.
     */
    fun getStatus(scanId: String): ScanStatusDto? {
        val entry = scans[scanId] ?: return null
        val elapsed = (Instant.now().epochSecond - entry.startedAt.epochSecond).toInt()
        val statusText = mapAuditStatus(entry)
        val findingsCount = getIssues(scanId).size
        val insertionPoints = try { entry.audit.insertionPointCount() } catch (_: Exception) { 0 }

        return ScanStatusDto(
            scan_id = scanId,
            status = statusText,
            target = entry.target,
            config = entry.config,
            started_at = entry.startedAt.atOffset(ZoneOffset.UTC)
                .format(DateTimeFormatter.ISO_OFFSET_DATE_TIME),
            insertion_points_total = insertionPoints,
            elapsed_seconds = elapsed,
            findings_count = findingsCount
        )
    }

    /**
     * Cancels a running scan. Returns true if found and cancelled.
     */
    fun cancel(scanId: String): Boolean {
        val entry = scans[scanId] ?: return false
        try {
            entry.audit.delete()
        } catch (e: Exception) {
            api.logging().logToError("Cancel scan $scanId: ${e.message}")
        }
        scans.remove(scanId)
        return true
    }

    /**
     * Returns audit issues for a specific scan, or all scans if scanId is null.
     */
    fun getIssues(scanId: String? = null): List<AuditIssue> {
        if (scanId != null) {
            val entry = scans[scanId] ?: return emptyList()
            return try {
                entry.audit.issues()
            } catch (_: Exception) {
                emptyList()
            }
        }
        // All issues across all scans
        return scans.values.flatMap { entry ->
            try {
                entry.audit.issues()
            } catch (_: Exception) {
                emptyList()
            }
        }
    }

    /**
     * Returns all scan IDs.
     */
    fun scanIds(): Set<String> = scans.keys.toSet()

    private fun mapAuditStatus(entry: ScanEntry): String {
        return try {
            val msg = entry.audit.statusMessage().lowercase()
            when {
                msg.contains("complete") || msg.contains("finished") -> "completed"
                msg.contains("cancel") -> "cancelled"
                msg.contains("error") || msg.contains("fail") -> "failed"
                else -> "running"
            }
        } catch (_: Exception) {
            "running"
        }
    }

    private fun isTerminal(entry: ScanEntry): Boolean {
        val status = mapAuditStatus(entry)
        return status == "completed" || status == "cancelled" || status == "failed"
    }

    private fun extractHost(raw: String): String {
        val hostLine = raw.lines().firstOrNull { it.startsWith("Host:", ignoreCase = true) }
        return hostLine?.substringAfter(":")?.trim()?.split(":")?.first() ?: "localhost"
    }

    private fun extractTarget(raw: String): String {
        val firstLine = raw.lines().firstOrNull() ?: return "unknown"
        val parts = firstLine.split(" ")
        return if (parts.size >= 2) "${parts[0]} ${parts[1]}" else firstLine
    }

    private fun generateId(): String {
        val chars = "0123456789abcdef"
        return (1..8).map { chars.random() }.joinToString("")
    }
}
