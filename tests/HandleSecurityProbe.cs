// ADR-024 test-only handle-derived security descriptor research.
// NEVER loaded from src/ or the diagnostic CLI. Existing directories only.
// The helper requests READ_CONTROL solely to query owner and DACL.
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using Microsoft.Win32.SafeHandles;

namespace WinTriageTests
{
    public static class HandleSecurityProbe
    {
        private const uint FILE_READ_ATTRIBUTES = 0x80;
        private const uint READ_CONTROL = 0x00020000;
        private const uint FILE_SHARE_READ = 1;
        private const uint FILE_SHARE_WRITE = 2;
        private const uint FILE_SHARE_DELETE = 4;
        private const uint OPEN_EXISTING = 3;
        private const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
        private const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
        private const uint FILE_ATTRIBUTE_DIRECTORY = 0x10;
        private const uint FILE_ATTRIBUTE_REPARSE_POINT = 0x400;
        private const uint OWNER_SECURITY_INFORMATION = 0x1;
        private const uint DACL_SECURITY_INFORMATION = 0x4;
        private const int ERROR_INSUFFICIENT_BUFFER = 122;
        private const uint MAX_TEST_DESCRIPTOR_BYTES = 65536;

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

        [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle OpenDirectoryNative(
            string path, uint access, uint share, IntPtr security,
            uint disposition, uint flags, IntPtr template);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetFileInformationByHandle(
            SafeFileHandle file, out ByHandleInfo info);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetKernelObjectSecurity(
            SafeFileHandle handle, uint requestedInformation,
            [Out] byte[] securityDescriptor, uint length, out uint lengthNeeded);

        private static ByHandleInfo Check(SafeFileHandle handle)
        {
            ByHandleInfo info;
            if (handle == null || handle.IsClosed || handle.IsInvalid ||
                !GetFileInformationByHandle(handle, out info) ||
                (info.Attributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
                (info.Attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
                throw new IOException("Test directory handle could not be validated.");
            return info;
        }

        private static SafeFileHandle Pin(string path, bool requestReadControl)
        {
            if (String.IsNullOrEmpty(path)) throw new ArgumentException("Missing test directory.");
            SafeFileHandle handle = OpenDirectoryNative(path,
                FILE_READ_ATTRIBUTES | (requestReadControl ? READ_CONTROL : 0),
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                IntPtr.Zero, OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, IntPtr.Zero);
            try
            {
                Check(handle);
                return handle;
            }
            catch
            {
                if (handle != null) handle.Dispose();
                throw;
            }
        }

        // Delete sharing is explicitly TEST-ONLY to permit a synthetic rename.
        // It does not grant delete access; no production share mode is changed.
        public static SafeFileHandle PinForSyntheticTest(string path)
        {
            return Pin(path, true);
        }

        public static SafeFileHandle PinWithoutReadControlForNegativeTest(string path)
        {
            return Pin(path, false);
        }

        public static string Identity(SafeFileHandle handle)
        {
            ByHandleInfo info = Check(handle);
            return info.VolumeSerial.ToString("X8") + ":" +
                info.FileIndexHigh.ToString("X8") + ":" + info.FileIndexLow.ToString("X8");
        }

        public static DirectorySecurity ReadSecurity(SafeFileHandle handle)
        {
            // Verify directory identity/reparse metadata before any security read.
            Check(handle);
            uint requested = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
            uint length;
            bool first = GetKernelObjectSecurity(handle, requested, null, 0, out length);
            int firstError = Marshal.GetLastWin32Error();
            if (first || firstError != ERROR_INSUFFICIENT_BUFFER ||
                length == 0 || length > MAX_TEST_DESCRIPTOR_BYTES)
                throw new IOException("Test handle security query refused (size).");
            byte[] buffer = new byte[(int)length];
            uint returned;
            if (!GetKernelObjectSecurity(handle, requested, buffer, (uint)buffer.Length, out returned) ||
                returned > buffer.Length)
                throw new IOException("Test handle security query refused (data).");
            DirectorySecurity descriptor = new DirectorySecurity();
            descriptor.SetSecurityDescriptorBinaryForm(buffer);
            return descriptor;
        }
    }
}
