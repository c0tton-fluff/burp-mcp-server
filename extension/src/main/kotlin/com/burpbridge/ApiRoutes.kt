package com.burpbridge

import burp.api.montoya.MontoyaApi
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.serialization.Serializable

// -- Request/Response DTOs --

@Serializable
data class HealthDto(
    val status: String,
    val burp_version: String,
    val extensions_loaded: Int,
    val bridge_version: String,
    val port: Int
)

@Serializable
data class ExtensionDto(
    val name: String,
    val loaded: Boolean,
    val has_scan_check: Boolean,
    val type: String
)

@Serializable
data class ExtensionsDto(
    val extensions: List<ExtensionDto>
)

@Serializable
data class ScanRequestDto(
    val request: String,
    val host: String = "",
    val port: Int = 443,
    val https: Boolean = true,
    val config: String = "active"
)

@Serializable
data class ScanStatusDto(
    val scan_id: String,
    val status: String,
    val target: String = "",
    val config: String = "",
    val started_at: String = "",
    val insertion_points_tested: Int = 0,
    val insertion_points_total: Int = 0,
    val elapsed_seconds: Int = 0,
    val findings_count: Int = 0
)

@Serializable
data class FindingDto(
    val name: String,
    val severity: String,
    val confidence: String,
    val url: String,
    val method: String,
    val detail: String,
    val extension: String,
    val request: String = "",
    val response: String = ""
)

@Serializable
data class FindingsDto(
    val count: Int,
    val findings: List<FindingDto>
)

@Serializable
data class ErrorDto(
    val error: String,
    val code: String
)

// -- Route installation --

fun Application.apiRoutes(
    api: MontoyaApi,
    scanManager: ScanManager,
    findingsStore: FindingsStore,
    extensionRegistry: ExtensionRegistry
) {
    routing {
        // GET /api/health
        get("/api/health") {
            val version = try {
                api.burpSuite().version().toString()
            } catch (e: Exception) {
                "unknown"
            }
            val extCount = extensionRegistry.count()
            call.respond(HealthDto(
                status = "ok",
                burp_version = version,
                extensions_loaded = extCount,
                bridge_version = BurpBridge.VERSION,
                port = BurpBridge.DEFAULT_PORT
            ))
        }

        // GET /api/extensions
        get("/api/extensions") {
            val nameFilter = call.request.queryParameters["name"]
            val typeFilter = call.request.queryParameters["type"]
            val extensions = extensionRegistry.list(nameFilter, typeFilter)
            call.respond(ExtensionsDto(extensions = extensions))
        }

        // POST /api/scan
        post("/api/scan") {
            val body = try {
                call.receive<ScanRequestDto>()
            } catch (e: Exception) {
                call.respond(HttpStatusCode.BadRequest, ErrorDto(
                    error = "invalid request body: ${e.message}",
                    code = "INVALID_REQUEST"
                ))
                return@post
            }

            if (body.request.isBlank()) {
                call.respond(HttpStatusCode.BadRequest, ErrorDto(
                    error = "request field is required",
                    code = "MISSING_REQUEST"
                ))
                return@post
            }

            // Montoya API only exposes LEGACY_ACTIVE_AUDIT_CHECKS and
            // LEGACY_PASSIVE_AUDIT_CHECKS. The config param maps to these.
            val passive = body.config.lowercase() == "passive"

            try {
                val status = scanManager.startScan(body, passive)
                call.respond(HttpStatusCode.Created, status)
            } catch (e: Exception) {
                api.logging().logToError("Scan start failed: ${e.message}")
                call.respond(HttpStatusCode.InternalServerError, ErrorDto(
                    error = "scan failed to start: ${e.message}",
                    code = "SCAN_ERROR"
                ))
            }
        }

        // GET /api/scan/{id}
        get("/api/scan/{id}") {
            val id = call.parameters["id"] ?: run {
                call.respond(HttpStatusCode.BadRequest, ErrorDto(
                    error = "scan_id required",
                    code = "MISSING_ID"
                ))
                return@get
            }
            val status = scanManager.getStatus(id)
            if (status == null) {
                call.respond(HttpStatusCode.NotFound, ErrorDto(
                    error = "scan $id not found",
                    code = "NOT_FOUND"
                ))
                return@get
            }
            call.respond(status)
        }

        // DELETE /api/scan/{id}
        delete("/api/scan/{id}") {
            val id = call.parameters["id"] ?: run {
                call.respond(HttpStatusCode.BadRequest, ErrorDto(
                    error = "scan_id required",
                    code = "MISSING_ID"
                ))
                return@delete
            }
            val cancelled = scanManager.cancel(id)
            if (!cancelled) {
                call.respond(HttpStatusCode.NotFound, ErrorDto(
                    error = "scan $id not found",
                    code = "NOT_FOUND"
                ))
                return@delete
            }
            call.respond(mapOf("status" to "cancelled"))
        }

        // GET /api/findings
        get("/api/findings") {
            val scanId = call.request.queryParameters["scan_id"]
            val severity = call.request.queryParameters["severity"]
            val confidence = call.request.queryParameters["confidence"]
            val extension = call.request.queryParameters["extension"]
            val url = call.request.queryParameters["url"]

            val findings = findingsStore.query(
                scanManager = scanManager,
                scanId = scanId,
                severity = severity,
                confidence = confidence,
                extension = extension,
                url = url
            )
            call.respond(FindingsDto(
                count = findings.size,
                findings = findings
            ))
        }
    }
}
