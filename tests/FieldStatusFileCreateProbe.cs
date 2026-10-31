// Test-only Win32 CreateFileW research probe (ADR-035).
// Never imported by production src/ or the user-facing field-status recorder.
// Writes ONLY caller-supplied invented bytes to a test-owned path; never overwrites.
using System;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace WinTriage.Research
{
    public static class FieldStatusFileCreateProbe
    {
        [StructLayout(LayoutKind.Sequential)]
        private struct SecurityAttributes
        {
            public int Length;
            public IntPtr SecurityDescriptor;
            public int InheritHandle;
        }

        [DllImport("kernel32.dll", EntryPoint = "CreateFileW",
            CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateFileNative(
            string path, uint desiredAccess, uint shareMode,
            ref SecurityAttributes securityAttributes, uint creationDisposition,
            uint flagsAndAttributes, IntPtr templateFile);

        // The caller MUST independently verify the DACL and trusted parent.
        // This proof of primitive behavior does not do parent-relative opens.
        public static void CreateNew(string path, byte[] descriptor, byte[] inventedContent)
        {
            if (String.IsNullOrEmpty(path) || descriptor == null || descriptor.Length == 0 ||
                inventedContent == null || inventedContent.Length > 32768)
                throw new ArgumentException("Invalid synthetic file request.");

            IntPtr nativeDescriptor = IntPtr.Zero;
            try
            {
                nativeDescriptor = Marshal.AllocHGlobal(descriptor.Length);
                Marshal.Copy(descriptor, 0, nativeDescriptor, descriptor.Length);
                SecurityAttributes attrs = new SecurityAttributes();
                attrs.Length = Marshal.SizeOf(typeof(SecurityAttributes));
                attrs.SecurityDescriptor = nativeDescriptor;
                attrs.InheritHandle = 0; // Never inherit file handle.

                // GENERIC_WRITE, no sharing, CREATE_NEW, FILE_ATTRIBUTE_NORMAL.
                // CREATE_NEW refuses both existing ordinary files and leaf links.
                // The supplied security descriptor is applied DURING creation,
                // without creating a default-permission interval or later Set-Acl.
                SafeFileHandle file = CreateFileNative(
                    path, 0x40000000U, 0U, ref attrs, 1U, 0x80U, IntPtr.Zero);
                if (file == null || file.IsInvalid)
                {
                    int error = Marshal.GetLastWin32Error();
                    if (file != null) file.Dispose();
                    // Numeric code only; never return filename, SID or file data.
                    throw new IOException("Synthetic CREATE_NEW refused. Win32=" + error);
                }
                using (file)
                using (FileStream stream = new FileStream(file, FileAccess.Write))
                {
                    stream.Write(inventedContent, 0, inventedContent.Length);
                    stream.Flush();
                }
            }
            finally
            {
                if (nativeDescriptor != IntPtr.Zero)
                    Marshal.FreeHGlobal(nativeDescriptor);
            }
        }
    }
}
