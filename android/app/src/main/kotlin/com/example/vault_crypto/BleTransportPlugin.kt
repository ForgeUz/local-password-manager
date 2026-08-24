package com.example.vault_crypto

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import com.google.android.gms.nearby.Nearby
import com.google.android.gms.nearby.connection.*
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.EventChannel
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel

/**
 * BLE Transport Plugin for Vault Crypto P2P Sync.
 *
 * Intent: Bridge Dart MethodChannel to Android Nearby Connections API.
 * Nearby Connections uses BLE for discovery + WiFi Direct for bulk transfer.
 *
 * Invariants:
 * - All payloads encrypted by Noise layer BEFORE reaching this plugin
 * - Service UUID is app-specific (not generic BLE)
 * - Zero-cloud doctrine: no data sent to internet
 * - 10m range enforced by BLE physical limitation
 *
 * State Transition:
 *   Idle -> PermissionsGranted -> Advertising/Scanning
 *   Scanning -> PeerDiscovered -> ConnectionRequested
 *   Connected -> DataExchange -> Disconnected
 *
 * Dependencies: Google Play Services Nearby Connections API
 */
class BleTransportPlugin private constructor(
    private val context: Context,
    private val flutterEngine: FlutterEngine
) : MethodChannel.MethodCallHandler, EventChannel.StreamHandler {

    companion object {
        // App-specific service ID for Nearby Connections
        // Must match on both devices
        private const val SERVICE_ID = "com.example.vault_crypto.sync"

        // Channel names (must match Dart side)
        private const val METHOD_CHANNEL = "com.example.vault_crypto/ble_transport"
        private const val EVENT_CHANNEL_PEERS = "com.example.vault_crypto/ble_peers"
        private const val EVENT_CHANNEL_DATA = "com.example.vault_crypto/ble_data"

        // Permission request code
        private const val PERMISSION_REQUEST_CODE = 1001

        /**
         * Register plugin with FlutterEngine.
         * Called from MainActivity.configureFlutterEngine().
         */
        fun registerWith(flutterEngine: FlutterEngine) {
            val context = flutterEngine.dartExecutor.binaryMessenger.let { 
                // Get context from FlutterEngine (requires FlutterActivity)
                // In production: pass context explicitly
                throw IllegalStateException("Context must be passed explicitly")
            }
        }

        /**
         * Register plugin with explicit context.
         * Preferred method for production.
         */
        fun registerWith(context: Context, flutterEngine: FlutterEngine) {
            val plugin = BleTransportPlugin(context, flutterEngine)

            // Method channel: Dart -> Kotlin commands
            MethodChannel(flutterEngine.dartExecutor.binaryMessenger, METHOD_CHANNEL)
                .setMethodCallHandler(plugin)

            // Event channel: Kotlin -> Dart peer discovery events
            EventChannel(flutterEngine.dartExecutor.binaryMessenger, EVENT_CHANNEL_PEERS)
                .setStreamHandler(plugin)

            // Event channel: Kotlin -> Dart incoming data events
            EventChannel(flutterEngine.dartExecutor.binaryMessenger, EVENT_CHANNEL_DATA)
                .setStreamHandler(plugin)
        }
    }

    private var methodChannel: MethodChannel? = null
    private var peerEventSink: EventChannel.EventSink? = null
    private var dataEventSink: EventChannel.EventSink? = null

    // Nearby Connections state
    private var connectedEndpointId: String? = null
    private var isAdvertising = false
    private var isDiscovering = false

    /**
     * Handle method calls from Dart.
     * Each method maps to a Nearby Connections API call.
     */
    override fun onMethodCall(call: MethodCall, result: MethodChannel.Result) {
        when (call.method) {
            "startAdvertising" -> {
                val deviceName = call.argument<String>("deviceName") ?: "Vault Crypto"
                startAdvertising(deviceName, result)
            }
            "stopAdvertising" -> stopAdvertising(result)
            "startScanning" -> startScanning(result)
            "stopScanning" -> stopScanning(result)
            "connect" -> {
                val peerId = call.argument<String>("peerId")
                if (peerId == null) {
                    result.error("INVALID_ARG", "peerId required", null)
                    return
                }
                connectToPeer(peerId, result)
            }
            "disconnect" -> disconnect(result)
            "sendData" -> {
                val data = call.argument<ByteArray>("data")
                if (data == null) {
                    result.error("INVALID_ARG", "data required", null)
                    return
                }
                sendData(data, result)
            }
            "isConnected" -> result.success(connectedEndpointId != null)
            else -> result.notImplemented()
        }
    }

    /**
     * Start advertising this device for discovery.
     * Uses P2P_CLUSTER strategy: BLE for discovery, WiFi Direct for data.
     */
    private fun startAdvertising(deviceName: String, result: MethodChannel.Result) {
        if (!hasBlePermissions()) {
            result.error("PERMISSION_DENIED", "BLE permissions not granted", null)
            return
        }

        val advertisingOptions = AdvertisingOptions.Builder()
            .setStrategy(Strategy.P2P_CLUSTER)
            .build()

        Nearby.getConnectionsClient(context)
            .startAdvertising(
                deviceName,
                SERVICE_ID,
                connectionLifecycleCallback,
                advertisingOptions
            )
            .addOnSuccessListener {
                isAdvertising = true
                result.success(true)
            }
            .addOnFailureListener { e ->
                result.error("ADVERTISE_FAILED", e.message, null)
            }
    }

    private fun stopAdvertising(result: MethodChannel.Result) {
        Nearby.getConnectionsClient(context).stopAdvertising()
        isAdvertising = false
        result.success(true)
    }

    /**
     * Start scanning for peer devices.
     * Discovered peers reported via EventChannel.
     */
    private fun startScanning(result: MethodChannel.Result) {
        if (!hasBlePermissions()) {
            result.error("PERMISSION_DENIED", "BLE permissions not granted", null)
            return
        }

        val discoveryOptions = DiscoveryOptions.Builder()
            .setStrategy(Strategy.P2P_CLUSTER)
            .build()

        Nearby.getConnectionsClient(context)
            .startDiscovery(SERVICE_ID, endpointDiscoveryCallback, discoveryOptions)
            .addOnSuccessListener {
                isDiscovering = true
                result.success(true)
            }
            .addOnFailureListener { e ->
                result.error("DISCOVERY_FAILED", e.message, null)
            }
    }

    private fun stopScanning(result: MethodChannel.Result) {
        Nearby.getConnectionsClient(context).stopDiscovery()
        isDiscovering = false
        result.success(true)
    }

    /**
     * Connect to a discovered peer.
     * After connection, WiFi Direct is established for bulk transfer.
     */
    private fun connectToPeer(peerId: String, result: MethodChannel.Result) {
        if (!hasBlePermissions()) {
            result.error("PERMISSION_DENIED", "BLE permissions not granted", null)
            return
        }

        Nearby.getConnectionsClient(context)
            .requestConnection(peerId, connectionLifecycleCallback)
            .addOnSuccessListener {
                result.success(true)
            }
            .addOnFailureListener { e ->
                result.error("CONNECT_FAILED", e.message, null)
            }
    }

    private fun disconnect(result: MethodChannel.Result) {
        connectedEndpointId?.let { endpointId ->
            Nearby.getConnectionsClient(context).disconnectFromEndpoint(endpointId)
            connectedEndpointId = null
        }
        result.success(true)
    }

    /**
     * Send encrypted data to connected peer.
     * Data MUST already be encrypted by Noise layer (Dart side).
     * This plugin never sees plaintext.
     */
    private fun sendData(data: ByteArray, result: MethodChannel.Result) {
        val endpointId = connectedEndpointId
        if (endpointId == null) {
            result.error("NOT_CONNECTED", "No peer connected", null)
            return
        }

        val payload = Payload.fromBytes(data)
        Nearby.getConnectionsClient(context)
            .sendPayload(endpointId, payload)
            .addOnSuccessListener {
                result.success(true)
            }
            .addOnFailureListener { e ->
                result.error("SEND_FAILED", e.message, null)
            }
    }

    /**
     * Connection lifecycle callback.
     * Handles: connection requested, accepted, rejected, disconnected.
     */
    private val connectionLifecycleCallback = object : ConnectionLifecycleCallback() {
        override fun onConnectionInitiated(endpointId: String, info: ConnectionInfo) {
            // Auto-accept for now (Noise handshake will authenticate)
            // In production: show confirmation dialog with peer name
            Nearby.getConnectionsClient(context)
                .acceptConnection(endpointId, payloadCallback)
        }

        override fun onConnectionResult(endpointId: String, result: ConnectionResolution) {
            when (result.status.statusCode) {
                ConnectionsStatusCodes.STATUS_OK -> {
                    connectedEndpointId = endpointId
                    methodChannel?.invokeMethod("onConnected", mapOf(
                        "endpointId" to endpointId
                    ))
                }
                ConnectionsStatusCodes.STATUS_CONNECTION_REJECTED -> {
                    methodChannel?.invokeMethod("onConnectionRejected", mapOf(
                        "endpointId" to endpointId
                    ))
                }
                else -> {
                    methodChannel?.invokeMethod("onConnectionFailed", mapOf(
                        "endpointId" to endpointId,
                        "statusCode" to result.status.statusCode
                    ))
                }
            }
        }

        override fun onDisconnected(endpointId: String) {
            if (connectedEndpointId == endpointId) {
                connectedEndpointId = null
                methodChannel?.invokeMethod("onDisconnected", mapOf(
                    "endpointId" to endpointId
                ))
            }
        }
    }

    /**
     * Endpoint discovery callback.
     * Reports discovered/lost peers via EventChannel.
     */
    private val endpointDiscoveryCallback = object : EndpointDiscoveryCallback() {
        override fun onEndpointFound(endpointId: String, info: DiscoveredEndpointInfo) {
            if (info.serviceId != SERVICE_ID) return

            peerEventSink?.success(mapOf(
                "type" to "found",
                "peerId" to endpointId,
                "deviceName" to info.endpointName,
                "serviceId" to info.serviceId
                // Note: RSSI not directly available in Nearby Connections
                // 10m range enforced by BLE physical limitation
            ))
        }

        override fun onEndpointLost(endpointId: String) {
            peerEventSink?.success(mapOf(
                "type" to "lost",
                "peerId" to endpointId
            ))
        }
    }

    /**
     * Payload callback for receiving data.
     * Data is encrypted — passed directly to Dart without inspection.
     */
    private val payloadCallback = object : PayloadCallback() {
        override fun onPayloadReceived(endpointId: String, payload: Payload) {
            if (payload.type == Payload.Type.BYTES) {
                val bytes = payload.asBytes() ?: return
                dataEventSink?.success(bytes)
            }
        }

        override fun onPayloadTransferUpdate(endpointId: String, update: PayloadTransferUpdate) {
            // Track transfer progress if needed
        }
    }

    /**
     * EventChannel.StreamHandler implementation.
     */
    override fun onListen(arguments: Any?, events: EventChannel.EventSink?) {
        // Determine which event channel based on arguments
        val channelName = (arguments as? Map<*, *>)?.get("channel") as? String
        when (channelName) {
            "peers" -> peerEventSink = events
            "data" -> dataEventSink = events
            else -> {
                // Fallback: assume it's the channel that was registered
                if (peerEventSink == null) {
                    peerEventSink = events
                } else if (dataEventSink == null) {
                    dataEventSink = events
                }
            }
        }
    }

    override fun onCancel(arguments: Any?) {
        peerEventSink = null
        dataEventSink = null
    }

    /**
     * Check if BLE permissions are granted.
     * Android 13+ (API 33): BLUETOOTH_CONNECT + BLUETOOTH_SCAN + NEARBY_WIFI_DEVICES
     * Android 12 and below: ACCESS_FINE_LOCATION
     */
    private fun hasBlePermissions(): Boolean {
        return if (Build.VERSION.SDK_INT >= 33) {
            ContextCompat.checkSelfPermission(
                context,
                Manifest.permission.BLUETOOTH_CONNECT
            ) == PackageManager.PERMISSION_GRANTED &&
            ContextCompat.checkSelfPermission(
                context,
                Manifest.permission.BLUETOOTH_SCAN
            ) == PackageManager.PERMISSION_GRANTED &&
            ContextCompat.checkSelfPermission(
                context,
                Manifest.permission.NEARBY_WIFI_DEVICES
            ) == PackageManager.PERMISSION_GRANTED
        } else {
            ContextCompat.checkSelfPermission(
                context,
                Manifest.permission.ACCESS_FINE_LOCATION
            ) == PackageManager.PERMISSION_GRANTED
        }
    }

    /**
     * Cleanup: stop all Nearby Connections.
     */
    fun dispose() {
        Nearby.getConnectionsClient(context).stopAllEndpoints()
    }
}