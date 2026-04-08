package com.burpbridge

import burp.api.montoya.MontoyaApi
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/**
 * Reads loaded extensions from Burp and merges with bundled registry
 * for capability tags (type, has_scan_check).
 */
class ExtensionRegistry(private val api: MontoyaApi) {

    @Serializable
    data class RegistryEntry(
        val name: String,
        val type: String = "unknown",
        val has_scan_check: Boolean = false
    )

    private val registry: Map<String, RegistryEntry> by lazy { loadBundledRegistry() }

    /**
     * Returns the count of loaded extensions.
     */
    fun count(): Int {
        return try {
            api.burpSuite().exportProjectOptionsAsJson().let { json ->
                parseExtensionCount(json)
            }
        } catch (e: Exception) {
            0
        }
    }

    /**
     * Lists extensions with optional name/type filters.
     */
    fun list(nameFilter: String? = null, typeFilter: String? = null): List<ExtensionDto> {
        val extensions = loadExtensions()
        return extensions
            .filter { ext ->
                (nameFilter == null || ext.name.contains(nameFilter, ignoreCase = true)) &&
                (typeFilter == null || ext.type.equals(typeFilter, ignoreCase = true))
            }
    }

    private fun loadExtensions(): List<ExtensionDto> {
        return try {
            val json = api.burpSuite().exportProjectOptionsAsJson()
            parseExtensions(json)
        } catch (e: Exception) {
            api.logging().logToError("Failed to load extensions: ${e.message}")
            emptyList()
        }
    }

    private fun parseExtensions(projectJson: String): List<ExtensionDto> {
        return try {
            val root = Json.parseToJsonElement(projectJson).jsonObject
            val userOptions = root["user_options"]?.jsonObject
            val extender = userOptions?.get("extender")?.jsonObject
            val extensions = extender?.get("extensions")?.jsonArray ?: return emptyList()

            extensions.mapNotNull { elem ->
                val obj = elem.jsonObject
                val name = obj["extension_name"]?.jsonPrimitive?.content ?: return@mapNotNull null
                val loaded = obj["loaded"]?.jsonPrimitive?.content?.toBoolean() ?: false

                // Look up in bundled registry for capability info
                val regEntry = registry[name.lowercase()]

                ExtensionDto(
                    name = name,
                    loaded = loaded,
                    has_scan_check = regEntry?.has_scan_check ?: false,
                    type = regEntry?.type ?: "unknown"
                )
            }
        } catch (e: Exception) {
            api.logging().logToError("Parse extensions failed: ${e.message}")
            emptyList()
        }
    }

    private fun parseExtensionCount(projectJson: String): Int {
        return try {
            val root = Json.parseToJsonElement(projectJson).jsonObject
            val userOptions = root["user_options"]?.jsonObject
            val extender = userOptions?.get("extender")?.jsonObject
            val extensions = extender?.get("extensions")?.jsonArray
            extensions?.count { elem ->
                elem.jsonObject["loaded"]?.jsonPrimitive?.content?.toBoolean() ?: false
            } ?: 0
        } catch (e: Exception) {
            0
        }
    }

    /**
     * Loads the bundled extensions.json registry from the classpath.
     * Maps lowercase extension name to capability metadata.
     */
    private fun loadBundledRegistry(): Map<String, RegistryEntry> {
        return try {
            val stream = javaClass.getResourceAsStream("/extensions.json")
                ?: return emptyMap()
            val content = stream.bufferedReader().readText()
            val entries = Json.decodeFromString<List<RegistryEntry>>(content)
            entries.associateBy { it.name.lowercase() }
        } catch (e: Exception) {
            api.logging().logToError("Failed to load extensions.json registry: ${e.message}")
            emptyMap()
        }
    }
}
