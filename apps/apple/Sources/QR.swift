import SwiftUI
import CoreImage
import CoreImage.CIFilterBuiltins
#if os(iOS)
import UIKit
import VisionKit
import AVFoundation
#else
import AppKit
#endif

/// QR codes for invites and device linking. Generated and read entirely on-device (Core Image /
/// VisionKit) — no network service ever sees a code.
enum QRCode {
    /// Render `text` as a crisp QR image, or nil if it can't be encoded.
    static func image(for text: String, scale: CGFloat = 10) -> CGImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(text.utf8)
        filter.correctionLevel = "M"
        guard let output = filter.outputImage?.transformed(by: CGAffineTransform(scaleX: scale, y: scale)) else { return nil }
        return CIContext().createCGImage(output, from: output.extent)
    }

    /// The first QR payload found in a still image.
    static func read(from image: CIImage) -> String? {
        let detector = CIDetector(ofType: CIDetectorTypeQRCode, context: nil,
                                  options: [CIDetectorAccuracy: CIDetectorAccuracyHigh])
        return detector?.features(in: image).compactMap { ($0 as? CIQRCodeFeature)?.messageString }.first
    }

    #if os(macOS)
    /// macOS: pick a screenshot / photo of a QR code and read it. (A Mac's camera rarely points at
    /// anything useful; an image someone sent is the common case.)
    @MainActor
    static func readFromImageFile() -> String? {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [.image]
        panel.allowsMultipleSelection = false
        panel.prompt = "Read QR code"
        guard panel.runModal() == .OK, let url = panel.url, let image = CIImage(contentsOf: url) else { return nil }
        return read(from: image)
    }
    #endif
}

/// A QR code on a white card (QR needs a light quiet zone to scan reliably on a dark UI).
struct QRCodeView: View {
    let text: String
    var size: CGFloat = 200

    var body: some View {
        Group {
            if let cg = QRCode.image(for: text) {
                Image(decorative: cg, scale: 1)
                    .interpolation(.none)
                    .resizable()
                    .scaledToFit()
            } else {
                Image(systemName: "qrcode").resizable().scaledToFit().foregroundStyle(.black.opacity(0.3))
            }
        }
        .padding(12)
        .frame(width: size, height: size)
        .background(.white, in: RoundedRectangle(cornerRadius: 16, style: .continuous))
        .accessibilityLabel("QR code")
    }
}

#if os(iOS)
/// Camera QR scanner (VisionKit). Returns the raw payload; the caller validates it — a scanned
/// code is untrusted input exactly like a pasted link.
struct QRScannerSheet: View {
    var prompt = "Point the camera at the QR code your host is showing."
    let onScan: (String) -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var denied = false

    var body: some View {
        NavigationStack {
            ZStack {
                Color.black.ignoresSafeArea()
                if DataScannerViewController.isSupported && !denied {
                    DataScanner(onScan: onScan).ignoresSafeArea()
                    VStack {
                        Spacer()
                        Text(prompt)
                            .font(.subheadline).foregroundStyle(.white).multilineTextAlignment(.center)
                            .padding(14).background(.black.opacity(0.55), in: RoundedRectangle(cornerRadius: 14))
                            .padding(24)
                    }
                } else {
                    VStack(spacing: 12) {
                        Image(systemName: "camera.fill").font(.largeTitle).foregroundStyle(.white.opacity(0.5))
                        Text(denied
                             ? "Skwod doesn't have camera access. Allow it in Settings, or paste the link instead."
                             : "This device can't scan QR codes here. Paste the link instead.")
                            .font(.subheadline).foregroundStyle(.white.opacity(0.7)).multilineTextAlignment(.center)
                    }
                    .padding(32)
                }
            }
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
            }
            .task {
                switch AVCaptureDevice.authorizationStatus(for: .video) {
                case .notDetermined: denied = !(await AVCaptureDevice.requestAccess(for: .video))
                case .authorized: denied = false
                default: denied = true
                }
            }
        }
    }

    private struct DataScanner: UIViewControllerRepresentable {
        let onScan: (String) -> Void

        func makeCoordinator() -> Coordinator { Coordinator(onScan: onScan) }

        func makeUIViewController(context: Context) -> DataScannerViewController {
            let vc = DataScannerViewController(
                recognizedDataTypes: [.barcode(symbologies: [.qr])],
                qualityLevel: .balanced, recognizesMultipleItems: false,
                isHighFrameRateTrackingEnabled: false, isHighlightingEnabled: true)
            vc.delegate = context.coordinator
            try? vc.startScanning()
            return vc
        }

        func updateUIViewController(_ vc: DataScannerViewController, context: Context) {}

        static func dismantleUIViewController(_ vc: DataScannerViewController, coordinator: Coordinator) {
            vc.stopScanning()
        }

        final class Coordinator: NSObject, DataScannerViewControllerDelegate {
            let onScan: (String) -> Void
            private var delivered = false
            init(onScan: @escaping (String) -> Void) { self.onScan = onScan }

            func dataScanner(_ dataScanner: DataScannerViewController, didAdd addedItems: [RecognizedItem], allItems: [RecognizedItem]) {
                guard !delivered else { return }
                for item in addedItems {
                    if case .barcode(let code) = item, let payload = code.payloadStringValue {
                        delivered = true
                        dataScanner.stopScanning()
                        onScan(payload)
                        return
                    }
                }
            }
        }
    }
}
#endif

/// The standard way to hand someone an invite or a code: the QR, the text, Copy and Share.
/// Everything copied from here is treated as sensitive (expires from the pasteboard).
struct ShareableCodeCard: View {
    let title: String
    let value: String
    var caption: String? = nil
    var qrSize: CGFloat = 190

    var body: some View {
        VStack(spacing: 12) {
            Text(title).font(.caption).foregroundStyle(.white.opacity(0.55))
            QRCodeView(text: value, size: qrSize)
            Text(value)
                .font(.system(.caption, design: .monospaced)).foregroundStyle(.white.opacity(0.85))
                .lineLimit(2).truncationMode(.middle).multilineTextAlignment(.center)
                .textSelection(.enabled)
            HStack(spacing: 10) {
                CopyButton(value, sensitive: true)
                ShareLink(item: value) {
                    Label("Share", systemImage: "square.and.arrow.up")
                }
                .buttonStyle(.glass)
            }
            if let caption {
                Text(caption).font(.caption2).foregroundStyle(.white.opacity(0.45)).multilineTextAlignment(.center)
            }
        }
        .frame(maxWidth: .infinity)
    }
}
