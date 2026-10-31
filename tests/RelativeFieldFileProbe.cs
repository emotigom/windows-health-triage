// ADR-036: test-only NT parent-handle-relative private file creation.
// Not a supported public Win32 API contract and never imported by production.
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Text.RegularExpressions;
using Microsoft.Win32.SafeHandles;

namespace WinTriageTests
{
    public static class RelativeFieldFileProbe
    {
        private const uint FILE_READ_ATTRIBUTES = 0x80;
        private const uint FILE_TRAVERSE = 0x20;
        private const uint FILE_ADD_FILE = 0x2;
        private const uint READ_CONTROL = 0x00020000;
        private const uint SYNCHRONIZE = 0x00100000;
        private const uint GENERIC_WRITE = 0x40000000;
        private const uint FILE_SHARE_READ = 1;
        private const uint FILE_SHARE_WRITE = 2;
        private const uint FILE_SHARE_DELETE = 4; // Test-only parent rename fixture.
        private const uint FILE_ATTRIBUTE_NORMAL = 0x80;
        private const uint FILE_ATTRIBUTE_DIRECTORY = 0x10;
        private const uint FILE_ATTRIBUTE_REPARSE_POINT = 0x400;
        private const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
        private const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
        private const uint OPEN_EXISTING = 3;
        private const uint FILE_CREATE = 2;
        private const uint FILE_NON_DIRECTORY_FILE = 0x40;
        private const uint FILE_SYNCHRONOUS_IO_NONALERT = 0x20;
        private const uint OBJ_CASE_INSENSITIVE = 0x40;
        private const uint OWNER_SECURITY_INFORMATION = 1;
        private const uint DACL_SECURITY_INFORMATION = 4;
        private const int ERROR_INSUFFICIENT_BUFFER = 122;
        private const int FILE_CREATED = 2;

        [StructLayout(LayoutKind.Sequential)]
        private struct UnicodeString
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct ObjectAttributes
        {
            public int Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct IoStatusBlock
        {
            public IntPtr Status;
            public IntPtr Information;
        }
        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        private struct ByHandleInfo
        {
            public uint Attributes;
            public long CreationTime;
            public long LastAccessTime;
            public long LastWriteTime;
            public uint VolumeSerial;
            public uint FileSizeHigh;
            public uint FileSizeLow;
            public uint NumberOfLinks;
            public uint FileIndexHigh;
            public uint FileIndexLow;
        }

        [DllImport("kernel32.dll", EntryPoint = "CreateFileW",
            CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle OpenDirectory(
            string path, uint access, uint share, IntPtr security,
            uint disposition, uint flags, IntPtr templateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetFileInformationByHandle(
            SafeFileHandle handle, out ByHandleInfo info);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetKernelObjectSecurity(
            SafeFileHandle handle, uint requested,
            [Out] byte[] descriptor, uint length, out uint needed);

        [DllImport("ntdll.dll", ExactSpelling = true)]
        private static extern int NtCreateFile(
            out SafeFileHandle handle, uint access, ref ObjectAttributes attributes,
            out IoStatusBlock status, IntPtr allocationSize, uint fileAttributes,
            uint shareAccess, uint disposition, uint options, IntPtr eaBuffer, uint eaLength);

        private static ByHandleInfo Check(SafeFileHandle handle, bool directory)
        {
            ByHandleInfo info;
            if (handle == null || handle.IsInvalid || handle.IsClosed ||
                !GetFileInformationByHandle(handle, out info) ||
                ((info.Attributes & FILE_ATTRIBUTE_DIRECTORY) != 0) != directory ||
                (info.Attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
                throw new IOException("Test handle is not a direct expected object.");
            return info;
        }

        // This lexical parent is merely an injected synthetic trust assumption.
        // No initial-root provenance, ancestor reparse or volume validation.
        public static SafeFileHandle PinSyntheticParent(string path)
        {
            if (String.IsNullOrEmpty(path)) throw new ArgumentException("Missing test parent.");
            SafeFileHandle h = OpenDirectory(path,
                FILE_READ_ATTRIBUTES | FILE_TRAVERSE | FILE_ADD_FILE | READ_CONTROL,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                IntPtr.Zero, OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, IntPtr.Zero);
            try { Check(h, true); return h; }
            catch { if (h != null) h.Dispose(); throw; }
        }

        public static string Identity(SafeFileHandle handle, bool directory)
        {
            ByHandleInfo info = Check(handle, directory);
            return info.VolumeSerial.ToString("X8") + ":" +
                info.FileIndexHigh.ToString("X8") + ":" + info.FileIndexLow.ToString("X8");
        }

        public static FileSecurity ReadCreatedFileSecurity(SafeFileHandle handle)
        {
            Check(handle, false);
            uint requested = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
            uint length;
            bool first = GetKernelObjectSecurity(handle, requested, null, 0, out length);
            int error = Marshal.GetLastWin32Error();
            if (first || error != ERROR_INSUFFICIENT_BUFFER || length == 0 || length > 65536)
                throw new IOException("Synthetic file security query refused.");
            byte[] buffer = new byte[(int)length];
            uint returned;
            if (!GetKernelObjectSecurity(handle, requested, buffer, (uint)buffer.Length, out returned) ||
                returned > buffer.Length)
                throw new IOException("Synthetic file security descriptor unavailable.");
            FileSecurity acl = new FileSecurity();
            acl.SetSecurityDescriptorBinaryForm(buffer);
            return acl;
        }

        // Exclusive creation relative to a *held* test-owned parent handle;
        // never resolves parent path again. Caller must dispose returned handle.
        public static SafeFileHandle CreateSyntheticChild(
            SafeFileHandle parent, string leaf, byte[] securityDescriptor)
        {
            if (parent == null || parent.IsInvalid || parent.IsClosed)
                throw new ArgumentException("Missing test parent handle.");
            if (String.IsNullOrEmpty(leaf) || leaf.Length > 85 ||
                !Regex.IsMatch(leaf, @"^[A-Za-z][A-Za-z0-9_-]{5,79}\.json$"))
                throw new ArgumentException("Invalid single-leaf status filename.");
            if (securityDescriptor == null || securityDescriptor.Length == 0 ||
                securityDescriptor.Length > 65536)
                throw new ArgumentException("Missing synthetic private ACL.");

            bool borrowed = false;
            IntPtr name = IntPtr.Zero;
            IntPtr namePointer = IntPtr.Zero;
            IntPtr securityPointer = IntPtr.Zero;
            SafeFileHandle child = null;
            try
            {
                parent.DangerousAddRef(ref borrowed);
                Check(parent, true);
                name = Marshal.StringToHGlobalUni(leaf);
                UnicodeString u = new UnicodeString();
                u.Buffer = name;
                u.Length = checked((ushort)(leaf.Length * 2));
                u.MaximumLength = checked((ushort)((leaf.Length + 1) * 2));
                namePointer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UnicodeString)));
                Marshal.StructureToPtr(u, namePointer, false);
                securityPointer = Marshal.AllocHGlobal(securityDescriptor.Length);
                Marshal.Copy(securityDescriptor, 0, securityPointer, securityDescriptor.Length);

                ObjectAttributes attributes = new ObjectAttributes();
                attributes.Length = Marshal.SizeOf(typeof(ObjectAttributes));
                attributes.RootDirectory = parent.DangerousGetHandle();
                attributes.ObjectName = namePointer;
                attributes.Attributes = OBJ_CASE_INSENSITIVE;
                attributes.SecurityDescriptor = securityPointer;

                IoStatusBlock io;
                int status = NtCreateFile(out child,
                    GENERIC_WRITE | READ_CONTROL | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                    ref attributes, out io, IntPtr.Zero, FILE_ATTRIBUTE_NORMAL,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    FILE_CREATE, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
                    IntPtr.Zero, 0);
                if (status != 0)
                    throw new IOException("Synthetic FILE_CREATE refused. NTSTATUS=0x" +
                        unchecked((uint)status).ToString("X8"));
                if (io.Information != new IntPtr(FILE_CREATED))
                    throw new IOException("Synthetic FILE_CREATE was not exclusive.");
                Check(child, false);
                SafeFileHandle result = child;
                child = null;
                return result;
            }
            finally
            {
                if (child != null) child.Dispose();
                if (securityPointer != IntPtr.Zero) Marshal.FreeHGlobal(securityPointer);
                if (namePointer != IntPtr.Zero) Marshal.FreeHGlobal(namePointer);
                if (name != IntPtr.Zero) Marshal.FreeHGlobal(name);
                if (borrowed) parent.DangerousRelease();
            }
        }
    }
}
