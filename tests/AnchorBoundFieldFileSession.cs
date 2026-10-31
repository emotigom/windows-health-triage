// ADR-037 TEST ONLY: couple an externally held *synthetic* reference to
// held-parent relative file creation. Never treats self-consistency as trust.
// Caller owns both handles and must establish reference provenance externally.
// No production imports, no reports, no path lookups, no cleanup or uploads.
using System;
using Microsoft.Win32.SafeHandles;

namespace WinTriageTests
{
    public sealed class AnchorBoundFieldFileSession : IDisposable
    {
        private readonly SyntheticAnchorLease lease;
        private readonly SafeFileHandle candidateParent;
        private readonly Guid sessionEpoch;
        private bool revoked;

        // A separate pre-existing reference is required: this class cannot
        // independently authenticate where that reference originated.
        public AnchorBoundFieldFileSession(
            SafeFileHandle externallyPinnedReference,
            SafeFileHandle independentlyOpenedCandidate,
            Guid epoch)
        {
            if (externallyPinnedReference == null ||
                independentlyOpenedCandidate == null ||
                Object.ReferenceEquals(externallyPinnedReference, independentlyOpenedCandidate))
                throw new ArgumentException("Distinct synthetic reference handles required.");
            sessionEpoch = epoch;
            lease = new SyntheticAnchorLease(externallyPinnedReference, epoch);
            try
            {
                lease.RequireSameObject(independentlyOpenedCandidate, epoch);
                candidateParent = independentlyOpenedCandidate; // Borrowed.
            }
            catch
            {
                lease.Dispose();
                throw;
            }
        }

        public void RequireCurrent(Guid epoch)
        {
            if (revoked) throw new ObjectDisposedException("AnchorBoundFieldFileSession");
            if (epoch != sessionEpoch || epoch == Guid.Empty)
                throw new InvalidOperationException("Synthetic epoch mismatch.");
            lease.RequireSameObject(candidateParent, epoch);
        }

        public SafeFileHandle CreateCheckedSyntheticChild(
            Guid epoch, string leaf, byte[] prevalidatedSecurityDescriptor)
        {
            RequireCurrent(epoch);
            SafeFileHandle created = RelativeFieldFileProbe.CreateSyntheticChild(
                candidateParent, leaf, prevalidatedSecurityDescriptor);
            try
            {
                // Revalidate the borrowed reference and independent parent
                // after create. Inspect the ACTUAL returned handle, not a path.
                RequireCurrent(epoch);
                RelativeFieldFileProbe.ReadCreatedFileSecurity(created);
                return created;
            }
            catch
            {
                created.Dispose();
                // Fail closed; never delete/relax a possibly created private file.
                throw;
            }
        }

        public void Dispose()
        {
            if (!revoked)
            {
                revoked = true;
                lease.Dispose(); // Does not close the caller's borrowed handles.
            }
        }
    }
}
