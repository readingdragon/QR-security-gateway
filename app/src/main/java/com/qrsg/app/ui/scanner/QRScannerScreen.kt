package com.qrsg.app.ui.scanner

import android.Manifest
import android.content.pm.PackageManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.Preview
import androidx.camera.core.Camera
import androidx.camera.core.CameraControl
import androidx.camera.core.CameraInfo
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import com.qrsg.app.domain.analyzer.LocalUrlAnalyzer
import com.qrsg.app.domain.analyzer.RiskLevel
import com.google.mlkit.vision.barcode.BarcodeScannerOptions
import com.google.mlkit.vision.barcode.BarcodeScanning
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.common.InputImage
import java.util.concurrent.Executors
import com.qrsg.app.domain.risk.HybridRiskEngine
import com.qrsg.app.domain.reputation.ReputationResult
import com.qrsg.app.data.history.ScanHistoryRepository
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.UUID
import androidx.annotation.OptIn
import androidx.camera.core.ExperimentalGetImage

@Composable
fun QRScannerScreen(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val context = LocalContext.current
    var hasCameraPermission by remember {
        mutableStateOf(
            ContextCompat.checkSelfPermission(
                context,
                Manifest.permission.CAMERA,
            ) == PackageManager.PERMISSION_GRANTED,
        )
    }
    var scannedValue by remember { mutableStateOf<String?>(null) }
    var scanError by remember { mutableStateOf<String?>(null) }
    val analysis = remember(scannedValue) {
        scannedValue?.let { LocalUrlAnalyzer.analyze(it) }
    }
    
    var onlineResult by remember(scannedValue) {
        mutableStateOf<ReputationResult?>(null)
    }
    
    var onlineCheckInProgress by remember(scannedValue) {
    mutableStateOf(false)
}
    val historyRepository = remember(context) { ScanHistoryRepository.get(context) }
    val historyId = remember(scannedValue) {
        if (scannedValue.isNullOrBlank()) null else UUID.randomUUID().toString()
    }
    val historyTime = remember(historyId) { System.currentTimeMillis() }
    var historySaveFailed by remember(historyId) { mutableStateOf(false) }

    LaunchedEffect(historyId, onlineResult) {
        val id = historyId
        val local = analysis
        if (id != null && local != null) {
            try {
                withContext(Dispatchers.IO) {
                    historyRepository.saveSnapshot(id, historyTime, local, onlineResult)
                }
                historySaveFailed = false
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: Exception) {
                historySaveFailed = true
            }
        }
    }

    val permissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestPermission(),
    ) { granted ->
        hasCameraPermission = granted
    }

    LaunchedEffect(Unit) {
        if (!hasCameraPermission) {
            permissionLauncher.launch(Manifest.permission.CAMERA)
        }
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(
            text = "QR Scanner",
            style = MaterialTheme.typography.headlineMedium,
            fontWeight = FontWeight.Bold,
        )

        Text(
            text = "Scan a QR code to inspect its contents before opening it.",
            style = MaterialTheme.typography.bodyMedium,
        )

        if (hasCameraPermission) {
            if (scannedValue == null) {
                CameraScannerPreview(
                    onQrDetected = { value ->
                        if (scannedValue == null) {
                            scannedValue = value
                        }
                    },
                    onError = { message ->
                        scanError = message
                    },
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(360.dp),
                )
            } else {
                Text(
                    text = "QR code detected",
                    style = MaterialTheme.typography.titleLarge,
                    color = MaterialTheme.colorScheme.primary,
                )
                Text(
                    text = scannedValue.orEmpty(),
                    style = MaterialTheme.typography.bodyLarge,
                )

                analysis?.let { result ->
                    FinalRiskSection(
                        assessment = HybridRiskEngine.assess(
                            local = result,
                            online = onlineResult
                        )
                    )
                    
                    Text(                        
                        text = result.title,
                        style = MaterialTheme.typography.titleMedium,
                        color = when (result.riskLevel) {
                            RiskLevel.SUSPICIOUS -> MaterialTheme.colorScheme.error
                            RiskLevel.UNVERIFIED -> MaterialTheme.colorScheme.tertiary
                            RiskLevel.LOW_RISK -> MaterialTheme.colorScheme.primary
                        },
                    )

                    result.reasons.forEach { reason ->
                        Text(
                            text = "• $reason",
                            style = MaterialTheme.typography.bodyMedium,
                        )
                    }
                }
                analysis?.let { result ->
                    OnlineReputationSection(
                        url = scannedValue.orEmpty(),
                        localResult = result,
                        onResultChange = { onlineResult = it },
                        onCheckingChange = { onlineCheckInProgress = it },
                    )

                    OpenScannedLinkButton(
                        rawValue = scannedValue.orEmpty(),
                        assessment = HybridRiskEngine.assess(result, onlineResult),
                        onlineCheckInProgress = onlineCheckInProgress,
                    )
                }
                if (historySaveFailed) {
                    Text("Could not save scan history.", color = MaterialTheme.colorScheme.error)
                }
                
                Text(
                    text = "Don't worry, QRSG never opens scanned links automatically.",
                    style = MaterialTheme.typography.bodyMedium,
                )
                Button(
                    onClick = {
                        scannedValue = null
                        scanError = null
                    },
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text("Scan another code")
                }
            }
        } else {
            Text("Camera permission is required to scan QR codes.")
            Button(
                onClick = {
                    permissionLauncher.launch(Manifest.permission.CAMERA)
                },
            ) {
                Text("Grant camera permission")
            }
        }

        scanError?.let { message ->
            Text(
                text = message,
                color = MaterialTheme.colorScheme.error,
            )
        }

        Spacer(Modifier.height(4.dp))

        OutlinedButton(
            onClick = onBack,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text("Back")
        }
    }
}

@OptIn(ExperimentalGetImage::class)
@Composable
private fun CameraScannerPreview(
    onQrDetected: (String) -> Unit,
    onError: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    val mainExecutor = remember(context) { ContextCompat.getMainExecutor(context) }
    val cameraExecutor = remember { Executors.newSingleThreadExecutor() }
    val scanner = remember {
        val options = BarcodeScannerOptions.Builder()
            .setBarcodeFormats(Barcode.FORMAT_QR_CODE)
            .build()
        BarcodeScanning.getClient(options)
    }
    val previewView = remember {
        PreviewView(context).apply {
            scaleType = PreviewView.ScaleType.FILL_CENTER
            implementationMode = PreviewView.ImplementationMode.COMPATIBLE
        }
    }

    var cameraProvider by remember {
        mutableStateOf<ProcessCameraProvider?>(null)
    }

    DisposableEffect(lifecycleOwner, previewView, scanner) {
        val providerFuture = ProcessCameraProvider.getInstance(context)
        val listener = Runnable {
            try {
                val provider = providerFuture.get()
                cameraProvider = provider

                val preview = Preview.Builder().build().also {
                    it.surfaceProvider = previewView.surfaceProvider
                }

                val analysis = ImageAnalysis.Builder()
                    .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                    .build()

                analysis.setAnalyzer(cameraExecutor) { imageProxy ->
                    val mediaImage = imageProxy.image
                    if (mediaImage == null) {
                        imageProxy.close()
                    } else {
                        val inputImage = InputImage.fromMediaImage(
                            mediaImage,
                            imageProxy.imageInfo.rotationDegrees,
                        )
                        scanner.process(inputImage)
                            .addOnSuccessListener(mainExecutor) { barcodes ->
                                val value = barcodes.firstNotNullOfOrNull { barcode ->
                                    barcode.rawValue
                                }
                                if (!value.isNullOrBlank()) {
                                    onQrDetected(value)
                                }
                            }
                            .addOnFailureListener(mainExecutor) {
                                onError("Could not read this QR code. Try again.")
                            }
                            .addOnCompleteListener {
                                imageProxy.close()
                            }
                    }
                }

                provider.unbindAll()
                provider.bindToLifecycle(
                    lifecycleOwner,
                    CameraSelector.DEFAULT_BACK_CAMERA,
                    preview,
                    analysis,
                )
            } catch (exception: Exception) {
                onError("Unable to start the camera: ${exception.message ?: "unknown error"}")
            }
        }

        providerFuture.addListener(listener, mainExecutor)

        onDispose {
            cameraProvider?.unbindAll()
            scanner.close()
            cameraExecutor.shutdown()
        }
    }

    AndroidView(
        factory = { previewView },
        modifier = modifier,
    )
}
