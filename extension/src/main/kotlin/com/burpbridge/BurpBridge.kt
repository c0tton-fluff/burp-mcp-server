package com.burpbridge

import burp.api.montoya.BurpExtension
import burp.api.montoya.MontoyaApi

class BurpBridge : BurpExtension {

    companion object {
        const val NAME = "Burp Bridge"
        const val VERSION = "1.0.0"
        const val DEFAULT_PORT = 9877
    }

    private var server: HttpServer? = null

    override fun initialize(api: MontoyaApi) {
        api.extension().setName(NAME)

        val port = resolvePort(api)
        val scanManager = ScanManager(api)
        val findingsStore = FindingsStore(api)
        val extensionRegistry = ExtensionRegistry(api)

        server = HttpServer(
            port = port,
            api = api,
            scanManager = scanManager,
            findingsStore = findingsStore,
            extensionRegistry = extensionRegistry
        )
        server!!.start()

        api.extension().registerUnloadingHandler {
            api.logging().logToOutput("$NAME shutting down...")
            server?.stop()
        }

        api.logging().logToOutput("$NAME $VERSION listening on :$port")
    }

    @Suppress("UNUSED_PARAMETER")
    private fun resolvePort(api: MontoyaApi): Int {
        // Could read from extension settings in the future.
        // For now, use the default.
        return DEFAULT_PORT
    }
}
