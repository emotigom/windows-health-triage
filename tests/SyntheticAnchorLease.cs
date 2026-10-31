// ADR-030 research ONLY: a caller-asserted synthetic reference handle is
// kept alive for one ephemeral session. This is NOT a trusted-root oracle.
// There is no user report access, filesystem mutation or production import.
using System;
using System.IO;
using Microsoft.Win32.SafeHandles;

namespace WinTriageTests
{
    public sealed class SyntheticAnchorLease : IDisposable
    {
        private readonly SafeFileHandle reference;
        private readonly string baselineFileId;
        private readonly Guid epoch;
        private bool revoked;

        // Caller must independently establish why reference is trusted.
        // This type cannot validate that claim, and never opens a path.
        public SyntheticAnchorLease(SafeFileHandle trustedReference, Guid sessionEpoch)
        {
            if (trustedReference == null || trustedReference.IsInvalid ||
                trustedReference.IsClosed)
                throw new ArgumentException("Missing held reference handle.");
            if (sessionEpoch == Guid.Empty)
                throw new ArgumentException("Missing synthetic session epoch.");
            reference = trustedReference; // BORROWED, caller retains ownership
            baselineFileId = VolumeIdentityProbe.FileIdentity(reference);
            epoch = sessionEpoch;
        }

        public void RequireSameObject(SafeFileHandle candidate, Guid sessionEpoch)
        {
            if (revoked)
                throw new ObjectDisposedException("SyntheticAnchorLease");
            if (sessionEpoch == Guid.Empty || sessionEpoch != epoch)
                throw new InvalidOperationException("Synthetic epoch mismatch.");
            if (reference.IsClosed || reference.IsInvalid)
                throw new InvalidOperationException("Synthetic reference handle expired.");
            if (candidate == null || candidate.IsClosed || candidate.IsInvalid)
                throw new ArgumentException("Missing synthetic candidate handle.");
            if (Object.ReferenceEquals(reference, candidate) ||
                reference.DangerousGetHandle() == candidate.DangerousGetHandle())
                throw new InvalidOperationException("Candidate is reference handle, not an independently acquired object.");
            // If the borrowed reference identity can no longer be read, fail
            // closed rather than trusting the stale cached baseline.
            VolumeIdentityProbe.RequireFileIdentity(reference, baselineFileId);
            VolumeIdentityProbe.RequireFileIdentity(candidate, baselineFileId);
        }

        public void Dispose()
        {
            revoked = true;
            // Never dispose the borrowed reference; caller owns it.
        }
    }
}
