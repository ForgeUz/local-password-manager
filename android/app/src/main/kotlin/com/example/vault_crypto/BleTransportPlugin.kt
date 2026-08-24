package com.example.vault_crypto

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.content.ContextCompat
import com.google.android.gms.nearby.Nearby
import com.google.android.gms.nearby.connection.AdvertisingOptions
import com.google.android.gms.nearby.connection.ConnectionInfo
import com.google.android.gms.nearby.connection.ConnectionLifecycleCallback
import com.google.android.gms.nearby.connection.ConnectionResolution
import com.google.android.gms.nearby.connection.ConnectionsStatusCodes
import com.google.android.gms.nearby.connection.DiscoveredEndpointInfo
import com.google.android.gms.nearby.connection.DiscoveryOptions
import com.google.android.gms.nearby.connection.EndpointDiscoveryCallback
import com.google.android.gms.nearby.connection.Payload
import com.google.android.gms.nearby.connection.PayloadCallback
import com.google.android.gms.nearby.connection.PayloadTransferUpdate
import com.google.android.gms.nearby.connection.Strategy
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.EventChannel
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel

/**
 * BLE Transport Plugin for Vault Crypto P2P Sync.
 * Bridges Dart MethodChannel to Android Nearby Connections API.
 *
 * FIX: hasBlePermissions() now checks the correct permission set per API level:
 *  - API 33+: BLUETOOTH_CONNECT + BLUETOOTH_SCAN + NEARBY_WIFI_DEVICES
 *  - API 31-32 (Android 12/12L): BLUETOOTH_CONNECT + BLUETOOTH_SCAN only
 *    (NEARBY_WIFI_DEVICES does not exist there; location NOT needed thanks
 *     to the neverForLocation flag in the manifest)
 *  - API <= 30: ACCESS_FINE_LOCATION (legacy BLE scanning requirement)
 */
class BleTransportPlugin private constructor(
    private val context: Context,
    private val flutterEngine: FlutterEngine
) : MethodChannel.MethodCallHandler, EventChannel.StreamHandler {

    companion object {
        private const val SERVICE_ID = "com.example.vault_crypto.sync"
        private const val METHOD_CHANNEL = "com.example.vault_crypto/ble_transport"
        private const val EVENT_CHANNEL_PEERS = "com.example.vault_crypto/ble_peers"
        private const val EVENT_CHANNEL_DATA = "com.example.vault_crypto/ble_data"

        fun registerWith(context: Context, flutterEngine: FlutterEngine): BleTransportPlugin {
            val plugin = BleTransportPlugin(context, flutterEngine)

            // FIX: keep a reference to the method channel so connection
            // callbacks (onConnected / onDisconnected) actually reach Dart.
            // Previously the channel was created but never stored ->
            // methodChannel stayed null -> UI hung on "Connecting...".
            val method = MethodChannel(flutterEngine.dartExecutor.binaryMessenger, METHOD_CHANNEL)
            method.setMethodCallHandler(plugin)
            plugin.methodChannel = method

            EventChannel(flutterEngine.dartExecutor.binaryMessenger, EVENT_CHANNEL_PEERS)
                .setStreamHandler(plugin)

            EventChannel(flutterEngine.dartExecutor.binaryMessenger, EVENT_CHANNEL_DATA)
                .setStreamHandler(plugin)

            return plugin
        }
    }

    private var methodChannel: MethodChannel? = null
    private var peerEventSink: EventChannel.EventSink? = null
    private var dataEventSink: EventChannel.EventSink? = null

    private var connectedEndpointId: String? = null
    private var isAdvertising = false
    private var isDiscovering = false

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
                isAdvertising = true; result.success(true)
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

    private fun startScanning(result: MethodChannel.Result) {
        if (!hasBlePermissions()) {
            result.error("PERMISSION_DENIED", "BLE permissions not granted", null)
            return
        }

        // Guard: Nearby throws STATUS_ALREADY_DISCOVERING (8002) if discovery
        // is already active. Stop-before-start prevents the re-entrancy bug.
        if (isDiscovering) {
            Nearby.getConnectionsClient(context).stopDiscovery()
            isDiscovering = false
        }

        val discoveryOptions = DiscoveryOptions.Builder()
            .setStrategy(Strategy.P2P_CLUSTER)
            .build()

        Nearby.getConnectionsClient(context)
            .startDiscovery(SERVICE_ID, endpointDiscoveryCallback, discoveryOptions)
            .addOnSuccessListener {
                isDiscovering = true; result.success(true)
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

    private fun connectToPeer(peerId: String, result: MethodChannel.Result) {
        if (!hasBlePermissions()) {
            result.error("PERMISSION_DENIED", "BLE permissions not granted", null)
            return
        }

        // Stop discovery before connecting: a live scan + connect on the same
        // client is a common source of flaky 8002/8003 status codes.
        if (isDiscovering) {
            Nearby.getConnectionsClient(context).stopDiscovery()
            isDiscovering = false
        }

        Nearby.getConnectionsClient(context)
            .requestConnection("Vault Crypto", peerId, connectionLifecycleCallback)
            .addOnSuccessListener { result.success(true) }
            .addOnFailureListener { e -> result.error("CONNECT_FAILED", e.message, null) }
    }

    private fun disconnect(result: MethodChannel.Result) {
        connectedEndpointId?.let { endpointId ->
            Nearby.getConnectionsClient(context).disconnectFromEndpoint(endpointId)
            connectedEndpointId = null
        }
        result.success(true)
    }

    private fun sendData(data: ByteArray, result: MethodChannel.Result) {
        val endpointId = connectedEndpointId
        if (endpointId == null) {
            result.error("NOT_CONNECTED", "No peer connected", null)
            return
        }

        val payload = Payload.fromBytes(data)
        Nearby.getConnectionsClient(context)
            .sendPayload(endpointId, payload)
            .addOnSuccessListener { result.success(true) }
            .addOnFailureListener { e -> result.error("SEND_FAILED", e.message, null) }
    }

    private val connectionLifecycleCallback = object : ConnectionLifecycleCallback() {
        override fun onConnectionInitiated(endpointId: String, info: ConnectionInfo) {
            android.util.Log.d("VaultCrypto", "onConnectionInitiated from $endpointId, auto-accept")
            Nearby.getConnectionsClient(context)
                .acceptConnection(endpointId, payloadCallback)
        }

        override fun onConnectionResult(endpointId: String, result: ConnectionResolution) {
            android.util.Log.d("VaultCrypto", "onConnectionResult status=${result.status.statusCode}")
            when (result.status.statusCode) {
                ConnectionsStatusCodes.STATUS_OK -> {
                    connectedEndpointId = endpointId
                    methodChannel?.invokeMethod("onConnected", mapOf("endpointId" to endpointId))
                }
                ConnectionsStatusCodes.STATUS_CONNECTION_REJECTED -> {
                    methodChannel?.invokeMethod("onConnectionRejected", mapOf("endpointId" to endpointId))
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
                methodChannel?.invokeMethod("onDisconnected", mapOf("endpointId" to endpointId))
            }
        }
    }

    private val endpointDiscoveryCallback = object : EndpointDiscoveryCallback() {
        override fun onEndpointFound(endpointId: String, info: DiscoveredEndpointInfo) {
            if (info.serviceId != SERVICE_ID) return
            peerEventSink?.success(mapOf(
                "type" to "found",
                "peerId" to endpointId,
                "deviceName" to info.endpointName,
                "serviceId" to info.serviceId
            ))
        }

        override fun onEndpointLost(endpointId: String) {
            peerEventSink?.success(mapOf("type" to "lost", "peerId" to endpointId))
        }
    }

    private val payloadCallback = object : PayloadCallback() {
        override fun onPayloadReceived(endpointId: String, payload: Payload) {
            if (payload.type == Payload.Type.BYTES) {
                val bytes = payload.asBytes() ?: return
                dataEventSink?.success(bytes)
            }
        }

        override fun onPayloadTransferUpdate(endpointId: String, update: PayloadTransferUpdate) {}
    }

    override fun onListen(arguments: Any?, events: EventChannel.EventSink?) {
        val channelName = (arguments as? Map<*, *>)?.get("channel") as? String
        when (channelName) {
            "peers" -> peerEventSink = events
            "data" -> dataEventSink = events
            else -> {
                if (peerEventSink == null) peerEventSink = events
                else if (dataEventSink == null) dataEventSink = events
            }
        }
    }

    override fun onCancel(arguments: Any?) {
        peerEventSink = null
        dataEventSink = null
    }

    /**
     * FIXED permission check per API level (see class doc).
     */
    private fun hasBlePermissions(): Boolean {
        val required = when {
            Build.VERSION.SDK_INT >= 33 -> listOf(
                Manifest.permission.BLUETOOTH_CONNECT,
                Manifest.permission.BLUETOOTH_SCAN,
                Manifest.permission.NEARBY_WIFI_DEVICES,
            )
            Build.VERSION.SDK_INT >= 31 -> listOf(
                Manifest.permission.BLUETOOTH_CONNECT,
                Manifest.permission.BLUETOOTH_SCAN,
            )
            else -> listOf(Manifest.permission.ACCESS_FINE_LOCATION)
        }
        val missing = required.filter {
            ContextCompat.checkSelfPermission(context, it) != PackageManager.PERMISSION_GRANTED
        }
        android.util.Log.d("VaultCrypto", "BLE permission check (SDK ${Build.VERSION.SDK_INT}), missing: $missing")
        return missing.isEmpty()
    }

    fun dispose() {
        Nearby.getConnectionsClient(context).stopAllEndpoints()
    }
}