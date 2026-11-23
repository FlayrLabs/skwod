import SwiftUI
import ImageIO
import UniformTypeIdentifiers

/// Every image this app decodes or sends goes through here.
///
/// **Inbound** (avatars, thumbnails, photos, full-size attachments — all chosen by someone else):
/// the header is read first and anything implausibly large is refused before a single pixel is
/// decoded, then the image is decoded straight to a bounded size. A 30 kB file that claims to be
/// 60 000 × 60 000 would otherwise allocate gigabytes the moment a view draws it, and because the
/// message stays in history it would do so again on every launch.
///
/// **Outbound** (photos the user attaches or posts): the picture is re-encoded from its pixels
/// alone, so nothing the camera wrote beside them — GPS position, device model, capture time,
/// embedded previews — leaves the device, encrypted or not.
enum SafeImage {
    /// Encoded bytes above this are not looked at as an image at all.
    static let maxEncodedBytes = 64 * 1024 * 1024
    /// Pixel count above this is refused from the header (`InboundImageRule`: ≈ 50 MP; a
    /// 48 MP phone photo passes).
    static let maxPixels = InboundImageRule.maxPixels
    /// Longest edge any inbound image is decoded to for display.
    static let displayEdge = 2048
    /// Longest edge of a photo we send (a full-resolution phone photo is ~4000–8000).
    static let outboundEdge = 4096

    /// Pixel size from the header only — nothing is decoded.
    static func pixelSize(_ source: CGImageSource) -> (width: Int, height: Int)? {
        guard let props = CGImageSourceCopyPropertiesAtIndex(source, 0, nil) as? [CFString: Any],
              let w = (props[kCGImagePropertyPixelWidth] as? NSNumber)?.intValue,
              let h = (props[kCGImagePropertyPixelHeight] as? NSNumber)?.intValue,
              w > 0, h > 0 else { return nil }
        return (w, h)
    }

    /// Whether `width × height` is a size this app is willing to decode.
    static func plausible(width: Int, height: Int) -> Bool {
        InboundImageRule.plausible(width: width, height: height)
    }

    private static func source(_ data: Data) -> CGImageSource? {
        guard !data.isEmpty, data.count <= maxEncodedBytes,
              let src = CGImageSourceCreateWithData(data as CFData, [kCGImageSourceShouldCache: false] as CFDictionary),
              // Only the formats phones and this app make: not every parser ImageIO has.
              InboundImageRule.allowed(typeIdentifier: CGImageSourceGetType(src) as String?),
              let size = pixelSize(src), plausible(width: size.width, height: size.height) else { return nil }
        return src
    }

    /// Decode `data` to at most `maxEdge` px on its long edge (orientation applied), or nil if it
    /// is not an image or fails the bounds above.
    static func decode(_ data: Data, maxEdge: Int = displayEdge) -> CGImage? {
        guard let src = source(data) else { return nil }
        let opts: [CFString: Any] = [
            kCGImageSourceCreateThumbnailFromImageAlways: true,
            kCGImageSourceThumbnailMaxPixelSize: maxEdge,
            kCGImageSourceCreateThumbnailWithTransform: true,
            kCGImageSourceShouldCacheImmediately: true,
        ]
        return CGImageSourceCreateThumbnailAtIndex(src, 0, opts as CFDictionary)
    }

    /// The uniform type of encoded image data, from its own header.
    static func type(of data: Data) -> UTType? {
        guard let src = CGImageSourceCreateWithData(data as CFData, nil),
              let id = CGImageSourceGetType(src) as String? else { return nil }
        return UTType(id)
    }

    /// A photo ready to send: re-encoded from pixels only (no EXIF, GPS, maker notes, XMP or
    /// embedded preview), orientation baked in, at most `maxEdge` px. PNG stays PNG (so
    /// transparency survives); everything else — JPEG, HEIC, TIFF, RAW — becomes JPEG.
    ///
    /// Returns nil when the data is not a still image this can re-encode. Animated images (GIF,
    /// APNG, animated WebP) are returned as nil too: re-encoding would freeze them, and callers
    /// send those as ordinary files. They carry no camera metadata.
    static func stripped(_ data: Data, maxEdge: Int = outboundEdge, quality: CGFloat = 0.85) -> (data: Data, type: UTType)? {
        guard let src = source(data), CGImageSourceGetCount(src) == 1,
              let cg = decode(data, maxEdge: maxEdge) else { return nil }
        let isPNG = (CGImageSourceGetType(src) as String?) == UTType.png.identifier
        let outType: UTType = isPNG ? .png : .jpeg
        let out = NSMutableData()
        guard let dest = CGImageDestinationCreateWithData(out, outType.identifier as CFString, 1, nil) else { return nil }
        // Only the pixels and a quality setting are handed over — no source properties.
        let props: [CFString: Any] = isPNG ? [:] : [kCGImageDestinationLossyCompressionQuality: quality]
        CGImageDestinationAddImage(dest, cg, props as CFDictionary)
        guard CGImageDestinationFinalize(dest) else { return nil }
        return (out as Data, outType)
    }

    /// True when encoded image data still carries location or camera metadata. Used by tests and
    /// the DEBUG self-check; the send path never relies on it (it always re-encodes).
    static func hasPrivateMetadata(_ data: Data) -> Bool {
        guard let src = CGImageSourceCreateWithData(data as CFData, nil),
              let props = CGImageSourceCopyPropertiesAtIndex(src, 0, nil) as? [CFString: Any] else { return false }
        if props[kCGImagePropertyGPSDictionary] != nil || props[kCGImagePropertyMakerAppleDictionary] != nil { return true }
        if let tiff = props[kCGImagePropertyTIFFDictionary] as? [CFString: Any],
           tiff[kCGImagePropertyTIFFMake] != nil || tiff[kCGImagePropertyTIFFModel] != nil { return true }
        if let exif = props[kCGImagePropertyExifDictionary] as? [CFString: Any],
           exif[kCGImagePropertyExifDateTimeOriginal] != nil || exif[kCGImagePropertyExifLensModel] != nil { return true }
        return false
    }

    // MARK: Decoded-image cache

    /// Views ask for the same thumbnail on every render; decode each once.
    private static let cache: NSCache<NSData, CGImage> = {
        let c = NSCache<NSData, CGImage>()
        c.countLimit = 300
        c.totalCostLimit = 192 * 1024 * 1024
        return c
    }()

    static func cached(_ data: Data, maxEdge: Int = displayEdge) -> CGImage? {
        let key = data as NSData
        if let hit = cache.object(forKey: key) { return hit }
        guard let cg = decode(data, maxEdge: maxEdge) else { return nil }
        cache.setObject(cg, forKey: key, cost: cg.bytesPerRow * cg.height)
        return cg
    }
}

extension Image {
    /// A SwiftUI `Image` from encoded image data someone else may have chosen (an avatar, a
    /// thumbnail, a photo). Bounded: see `SafeImage`. Nil if it isn't an acceptable image.
    init?(data: Data) {
        guard let cg = SafeImage.cached(data) else { return nil }
        self.init(decorative: cg, scale: 1)
    }
}
