import Darwin
import Foundation
import Security
import SluiceCoreHash

struct CoreValidationError: LocalizedError {
    let errorDescription: String?
    init(_ message: String) { errorDescription = message }
}

func embeddedCoreCDHashes() -> Set<String> {
    guard let slot = sluice_core_cdhash_slot() else { return [] }
    var bytes: [UInt8] = []
    // 200 bytes minus the C slot's 19-byte marker; never read outside the slot.
    for i in 0..<181 {
        let byte = UInt8(bitPattern: slot[i])
        if byte == 0 { break }
        bytes.append(byte)
    }
    return Set(String(decoding: bytes, as: UTF8.self).split(separator: ",").map(String.init))
}

func validateCore(at url: URL, teamID: String?, expectedHashes: Set<String> = embeddedCoreCDHashes()) throws {
    var code: SecStaticCode?
    guard SecStaticCodeCreateWithPath(url as CFURL, [], &code) == errSecSuccess, let code else {
        throw CoreValidationError("core signature could not be read")
    }
    var requirement: SecRequirement?
    if let teamID {
        let rule = "anchor apple generic and identifier \"dev.sluice.core\" and certificate leaf[subject.OU] = \"\(teamID)\""
        guard SecRequirementCreateWithString(rule as CFString, [], &requirement) == errSecSuccess else {
            throw CoreValidationError("core signing requirement could not be created")
        }
    }
    let flags = SecCSFlags(rawValue: kSecCSCheckAllArchitectures | kSecCSStrictValidate)
    let status = SecStaticCodeCheckValidity(code, flags, requirement)
    guard status == errSecSuccess else {
        throw CoreValidationError("core signature validation failed (\(status))")
    }
    if teamID == nil {
        guard !expectedHashes.isEmpty else {
            throw CoreValidationError("no core cdhashes embedded in helper; rebuild with record-core-cdhash.sh")
        }
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
              let dict = info as? [String: Any], let hash = dict[kSecCodeInfoUnique as String] as? Data,
              expectedHashes.contains(hash.map { String(format: "%02x", $0) }.joined()) else {
            throw CoreValidationError("core cdhash does not match this helper's build")
        }
    }
}

/// Reject symlinks and writable ancestors too: otherwise an attacker could rename the
/// staging directory after validation and change the path passed to Process.run().
func prepareStageDirectory(_ path: String) throws -> URL {
    guard path.hasPrefix("/") else { throw CoreValidationError("helper staging directory must be absolute") }
    let directory = URL(fileURLWithPath: path).standardizedFileURL
    var current = URL(fileURLWithPath: "/", isDirectory: true)
    for component in directory.pathComponents.dropFirst() {
        current.appendPathComponent(component, isDirectory: true)
        var st = stat()
        if lstat(current.path, &st) != 0 {
            guard errno == ENOENT, mkdir(current.path, 0o700) == 0, lstat(current.path, &st) == 0 else {
                throw CoreValidationError("can't create helper staging directory at \(current.path)")
            }
        }
        let isStage = current.path == directory.path
        guard (st.st_mode & S_IFMT) == S_IFDIR,
              (isStage ? st.st_uid == geteuid() : (st.st_uid == 0 || st.st_uid == geteuid())),
              st.st_mode & 0o022 == 0 else {
            throw CoreValidationError("unsafe helper staging directory at \(current.path): must be a directory owned by \(isStage ? "the helper" : "root or the helper") and not group/other-writable")
        }
    }
    // '/' is not a suitable staging directory, even when running as root.
    guard directory.path != "/" else { throw CoreValidationError("invalid helper staging directory") }
    return directory
}

/// Copy bytes into a fresh, helper-owned file, without preserving source ownership,
/// ACLs, symlinks or hard links. Only this protected copy is verified and executed.
func stageCore(from source: String, in directory: String, teamID: String?,
               expectedHashes: Set<String> = embeddedCoreCDHashes()) throws -> URL {
    let root = try prepareStageDirectory(directory)
    let runDirectory = root.appendingPathComponent(UUID().uuidString, isDirectory: true)
    guard mkdir(runDirectory.path, 0o700) == 0 else {
        throw CoreValidationError("can't create private core staging directory")
    }
    do {
        let inputFD = open(source, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard inputFD >= 0 else { throw CoreValidationError("can't open core binary at \(source)") }
        let input = FileHandle(fileDescriptor: inputFD, closeOnDealloc: true)
        defer { try? input.close() }
        var st = stat()
        guard fstat(inputFD, &st) == 0, st.st_mode & S_IFMT == S_IFREG else {
            throw CoreValidationError("core binary is not a regular file")
        }
        let copy = runDirectory.appendingPathComponent("sluice")
        let outputFD = open(copy.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard outputFD >= 0 else { throw CoreValidationError("can't create staged core") }
        let output = FileHandle(fileDescriptor: outputFD, closeOnDealloc: true)
        defer { try? output.close() }
        while let bytes = try input.read(upToCount: 1024 * 1024), !bytes.isEmpty {
            try output.write(contentsOf: bytes)
        }
        guard fchmod(outputFD, 0o500) == 0 else { throw CoreValidationError("can't protect staged core") }
        try output.close()
        try validateCore(at: copy, teamID: teamID, expectedHashes: expectedHashes)
        return copy
    } catch {
        try? FileManager.default.removeItem(at: runDirectory)
        throw error
    }
}
