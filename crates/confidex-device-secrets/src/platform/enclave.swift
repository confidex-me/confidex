import CryptoKit
import Foundation
import LocalAuthentication
import Security

private enum Failure: Error { case invalid, unavailable }
private func context(_ interaction: UInt8) -> LAContext {
    let context = LAContext()
    context.interactionNotAllowed = interaction == 0
    context.localizedReason = "Open a Confidex local key"
    return context
}
private func code(_ error: Error) -> Int32 {
    if let failure = error as? Failure { return failure == .invalid ? -50 : -4 }
    let error = error as NSError
    if error.domain == NSOSStatusErrorDomain { return Int32(error.code) }
    if error.domain == LAError.errorDomain {
        switch error.code {
        case LAError.userCancel.rawValue, LAError.appCancel.rawValue, LAError.systemCancel.rawValue: return -128
        case LAError.notInteractive.rawValue: return -25308
        default: return -25293
        }
    }
    if let underlying = error.userInfo[NSUnderlyingErrorKey] as? Error { return code(underlying) }
    return -50
}
private func output(_ data: Data, _ out: UnsafeMutablePointer<UInt8>, _ capacity: Int, _ size: UnsafeMutablePointer<Int>) throws {
    guard data.count <= capacity else { throw Failure.invalid }
    data.copyBytes(to: out, count: data.count)
    size.pointee = data.count
}
@_cdecl("confidex_enclave_capabilities")
public func capabilities() -> Int32 {
    guard SecureEnclave.isAvailable else { return -4 }
    let probe = LAContext()
    return probe.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
        && probe.biometryType == .touchID ? 2 : 1
}
@_cdecl("confidex_enclave_seal")
public func seal(_ binding: UnsafePointer<UInt8>, _ key: UnsafePointer<UInt8>, _ verified: UInt8, _ interaction: UInt8,
                 _ out: UnsafeMutablePointer<UInt8>, _ capacity: Int, _ size: UnsafeMutablePointer<Int>) -> Int32 {
    do {
        guard SecureEnclave.isAvailable else { throw Failure.unavailable }
        var flags: SecAccessControlCreateFlags = [.privateKeyUsage]
        if verified != 0 { flags.insert(.biometryCurrentSet) }
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags, &error) else {
            if let error = error?.takeRetainedValue() { throw error }
            throw Failure.unavailable
        }
        let root = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access, authenticationContext: context(interaction))
        let ephemeral = P256.KeyAgreement.PrivateKey()
        let blob = root.dataRepresentation
        guard blob.count < 4096 else { throw Failure.invalid }
        var header = Data([UInt8(blob.count & 255), UInt8(blob.count >> 8)])
        header.append(blob)
        header.append(ephemeral.publicKey.x963Representation)
        let binding = Data(bytes: binding, count: 32)
        let shared = try ephemeral.sharedSecretFromKeyAgreement(with: root.publicKey)
        let wrapping = shared.hkdfDerivedSymmetricKey(using: SHA256.self, salt: binding, sharedInfo: header, outputByteCount: 32)
        var plain = Data(bytes: key, count: 32)
        defer { plain.resetBytes(in: plain.startIndex..<plain.endIndex) }
        let box = try AES.GCM.seal(plain, using: wrapping, authenticating: binding + header)
        guard let combined = box.combined else { throw Failure.invalid }
        try output(header + combined, out, capacity, size)
        return 0
    } catch { return code(error) }
}
@_cdecl("confidex_enclave_unseal")
public func unseal(_ binding: UnsafePointer<UInt8>, _ bytes: UnsafePointer<UInt8>, _ count: Int, _ interaction: UInt8,
                   _ out: UnsafeMutablePointer<UInt8>, _ capacity: Int, _ size: UnsafeMutablePointer<Int>) -> Int32 {
    do {
        guard SecureEnclave.isAvailable else { throw Failure.unavailable }
        guard count >= 127 && count <= 8192 else { throw Failure.invalid }
        let data = Data(bytes: bytes, count: count)
        let length = Int(data[0]) | Int(data[1]) << 8
        let prefix = 2 + length + 65
        guard length > 0 && length < 4096 && count == prefix + 60 else { throw Failure.invalid }
        let root = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: data[2..<2+length], authenticationContext: context(interaction))
        let publicKey = try P256.KeyAgreement.PublicKey(x963Representation: data[2+length..<prefix])
        let binding = Data(bytes: binding, count: 32)
        let header = data[..<prefix]
        let shared = try root.sharedSecretFromKeyAgreement(with: publicKey)
        let wrapping = shared.hkdfDerivedSymmetricKey(using: SHA256.self, salt: binding, sharedInfo: header, outputByteCount: 32)
        let box = try AES.GCM.SealedBox(combined: data[prefix...])
        var plain = try AES.GCM.open(box, using: wrapping, authenticating: binding + header)
        defer { plain.resetBytes(in: plain.startIndex..<plain.endIndex) }
        guard plain.count == 32 else { throw Failure.invalid }
        try output(plain, out, capacity, size)
        return 0
    } catch { return code(error) }
}
