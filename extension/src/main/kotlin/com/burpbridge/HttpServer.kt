package com.burpbridge

import burp.api.montoya.MontoyaApi
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.server.plugins.contentnegotiation.*
import kotlinx.serialization.json.Json

class HttpServer(
    private val port: Int,
    private val api: MontoyaApi,
    private val scanManager: ScanManager,
    private val findingsStore: FindingsStore,
    private val extensionRegistry: ExtensionRegistry
) {
    private var engine: NettyApplicationEngine? = null

    fun start() {
        engine = embeddedServer(Netty, port = port, host = "127.0.0.1") {
            install(ContentNegotiation) {
                json(Json {
                    prettyPrint = false
                    encodeDefaults = true
                    ignoreUnknownKeys = true
                })
            }
            apiRoutes(api, scanManager, findingsStore, extensionRegistry)
        }
        engine!!.start(wait = false)
    }

    fun stop() {
        engine?.stop(gracePeriodMillis = 500, timeoutMillis = 1000)
    }
}
