package com.burpbridge

import burp.api.montoya.MontoyaApi
import burp.api.montoya.scanner.audit.issues.AuditIssue

/**
 * Converts Montoya AuditIssue objects into FindingDto with filtering.
 * Issues are pulled from ScanManager's Audit handles (no global issues() API).
 * Evidence (request/response) truncated to 10KB each.
 */
class FindingsStore(private val api: MontoyaApi) {

    companion object {
        const val MAX_EVIDENCE_BYTES = 10_000
    }

    /**
     * Query issues from scan audits with optional filters.
     * All string filters are substring matches (case-insensitive).
     */
    fun query(
        scanManager: ScanManager,
        scanId: String? = null,
        severity: String? = null,
        confidence: String? = null,
        extension: String? = null,
        url: String? = null
    ): List<FindingDto> {
        val issues: List<AuditIssue> = scanManager.getIssues(scanId)

        return issues.mapNotNull { issue: AuditIssue ->
            try {
                mapIssue(issue)
            } catch (_: Exception) {
                null
            }
        }.filter { finding ->
            (severity == null || finding.severity.equals(severity, ignoreCase = true)) &&
            (confidence == null || finding.confidence.equals(confidence, ignoreCase = true)) &&
            (extension == null || finding.extension.contains(extension, ignoreCase = true)) &&
            (url == null || finding.url.contains(url, ignoreCase = true))
        }
    }

    private fun mapIssue(issue: AuditIssue): FindingDto {
        val issueSeverity = issue.severity().name.lowercase()
        val issueConfidence = issue.confidence().name.lowercase()
        val issueUrl = issue.baseUrl() ?: ""
        val issueName = issue.name() ?: "Unknown"
        val issueDetail = (issue.detail() ?: "").take(2000)

        // Extension name from issue definition
        val issueExtension = try {
            issue.definition().name() ?: "Burp Scanner"
        } catch (_: Exception) {
            "Burp Scanner"
        }

        // Method from first request/response
        val method = try {
            issue.requestResponses().firstOrNull()?.request()?.method() ?: "GET"
        } catch (_: Exception) {
            "GET"
        }

        val (reqEvidence, respEvidence) = extractEvidence(issue)

        return FindingDto(
            name = issueName,
            severity = issueSeverity,
            confidence = issueConfidence,
            url = issueUrl,
            method = method,
            detail = issueDetail,
            extension = issueExtension,
            request = reqEvidence,
            response = respEvidence
        )
    }

    private fun extractEvidence(issue: AuditIssue): Pair<String, String> {
        return try {
            val rr = issue.requestResponses().firstOrNull() ?: return Pair("", "")
            val req = rr.request()?.toString()?.take(MAX_EVIDENCE_BYTES) ?: ""
            val resp = rr.response()?.toString()?.take(MAX_EVIDENCE_BYTES) ?: ""
            Pair(req, resp)
        } catch (_: Exception) {
            Pair("", "")
        }
    }
}
