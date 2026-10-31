// Copyright (c) contributors to Windows Health Triage. MIT licensed.
// Windows-only, no external dependency. Native Windows CreateDirectoryW
// atomically fails when the target already exists (ERROR_ALREADY_EXISTS).
// The supplied security descriptor is applied at directory creation time.
using System;
using System.IO;
using System.Runtime.InteropServices;

namespace WinTriage
{
    public static class NativeReportDirectory
    {
        [StructLayout(LayoutKind.Sequential)]
        private struct SecurityAttributes
        {
            public int Length;
            public IntPtr SecurityDescriptor;
            public int InheritHandle;
        }

        [DllImport("kernel32.dll", EntryPoint = "CreateDirectoryW",
            CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CreateDirectoryNative(
            string path, ref SecurityAttributes attributes);

        // No creation fallback; an existing directory must never be reused,
        // even if its ACL happens to match the current account.
        public static void CreateNew(string path, byte[] descriptor)
        {
            if (String.IsNullOrEmpty(path) || descriptor == null || descriptor.Length == 0)
                throw new ArgumentException("Missing report directory security descriptor.");
            IntPtr nativeDescriptor = IntPtr.Zero;
            try
            {
                nativeDescriptor = Marshal.AllocHGlobal(descriptor.Length);
                Marshal.Copy(descriptor, 0, nativeDescriptor, descriptor.Length);
                SecurityAttributes attrs = new SecurityAttributes();
                attrs.Length = Marshal.SizeOf(typeof(SecurityAttributes));
                attrs.SecurityDescriptor = nativeDescriptor;
                attrs.InheritHandle = 0;
                bool created = CreateDirectoryNative(path, ref attrs);
                if (!created)
                {
                    int error = Marshal.GetLastWin32Error();
                    if (error == 183)
                        throw new IOException("Report directory already exists; refusing reuse.");
                    // Fixed numeric Win32 code: no path, host, user, ACL or log data.
                    throw new IOException("Private report directory creation failed. Win32=" + error);
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
