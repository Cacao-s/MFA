package com.zeyanlin.mfa.platform

import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.MultiFormatReader
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.common.HybridBinarizer

/**
 * Decodes QR codes out of the camera preview (spec §1).
 *
 * ZXing rather than ML Kit: it works offline and pulls in no Play Services.
 * This app does not talk to Google, and a QR decoder is not worth making it
 * start.
 *
 * Only the luminance plane is read, and only inside this method — no frame is
 * copied anywhere else, written to disk, or kept after the callback returns.
 */
class QrAnalyzer(private val onPayload: (String) -> Unit) : ImageAnalysis.Analyzer {

    private val reader = MultiFormatReader().apply {
        setHints(
            mapOf(
                DecodeHintType.POSSIBLE_FORMATS to listOf(com.google.zxing.BarcodeFormat.QR_CODE),
                // Worth the extra work: a code photographed off a screen is
                // often slightly skewed or low contrast.
                DecodeHintType.TRY_HARDER to true,
            ),
        )
    }

    override fun analyze(image: ImageProxy) {
        try {
            val plane = image.planes.firstOrNull() ?: return
            val buffer = plane.buffer
            val bytes = ByteArray(buffer.remaining())
            buffer.get(bytes)

            val source = PlanarYUVLuminanceSource(
                bytes,
                plane.rowStride,
                image.height,
                0,
                0,
                image.width,
                image.height,
                false,
            )

            val result = runCatching {
                reader.decodeWithState(BinaryBitmap(HybridBinarizer(source)))
            }.getOrNull()

            result?.text?.let(onPayload)
        } finally {
            // Not closing the proxy stalls the pipeline after a few frames.
            reader.reset()
            image.close()
        }
    }
}
