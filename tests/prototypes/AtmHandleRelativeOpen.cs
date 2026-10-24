// ADR-0011 study (P1-C): an ISOLATED PROTOTYPE, test code only - never part of the shipped engine.
// Opens a file for reading relative to a handle of its volume root, with OBJ_DONT_REPARSE: the kernel refuses a
// reparse point in any component of the name in the same call that opens the file (no window between a check and the
// open). The volume root must be a fixed drive; anything else is refused before any open. Read-only, shares read,
// write and delete with everyone, and closes every handle it opens.
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace AgentTempManagerPrototype
{
    public static class AtmHandleRelativeOpen
    {
        [StructLayout(LayoutKind.Sequential)]
        private struct UnicodeString { public ushort Length; public ushort MaximumLength; public IntPtr Buffer; }

        [StructLayout(LayoutKind.Sequential)]
        private struct ObjectAttributes { public int Length; public IntPtr RootDirectory; public IntPtr ObjectName; public uint Attributes; public IntPtr SecurityDescriptor; public IntPtr SecurityQualityOfService; }

        [StructLayout(LayoutKind.Sequential)]
        private struct IoStatusBlock { public IntPtr Status; public IntPtr Information; }

        [DllImport("ntdll.dll")]
        private static extern int NtCreateFile(out SafeFileHandle handle, uint access, ref ObjectAttributes attributes, out IoStatusBlock io, IntPtr allocation, uint fileAttributes, uint share, uint disposition, uint options, IntPtr ea, uint eaLength);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr sa, uint disposition, uint flags, IntPtr template);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        private static extern uint GetDriveTypeW(string root);

        private const uint ObjCaseInsensitive = 0x40;
        private const uint ObjDontReparse = 0x1000;

        // NTSTATUS of opening -path (X:\...) for reading; 0 = opened (and closed again). 0xC000050B
        // (STATUS_REPARSE_POINT_ENCOUNTERED) when a component is a reparse point and -dontReparse is set. Returns
        // unchecked((int)0xC0000022) style statuses as they come; -1 when the path is not drive-absolute; -2 when the
        // drive is not fixed; -3 when the volume root cannot be opened.
        public static int Open(string path, bool dontReparse)
        {
            if (string.IsNullOrEmpty(path) || path.Length < 4 || path[1] != ':' || path[2] != '\\' || !char.IsLetter(path[0])) return -1;
            string rootPath = path.Substring(0, 3);
            if (GetDriveTypeW(rootPath) != 3) return -2;
            // The volume root is opened normally: the drive letter is an object-manager link, which OBJ_DONT_REPARSE
            // would refuse; every component below it is parsed with the flag.
            using (SafeFileHandle root = CreateFileW(rootPath, 0x80000000, 7, IntPtr.Zero, 3, 0x02000000, IntPtr.Zero))
            {
                if (root.IsInvalid) return -3;
                string rel = path.Substring(3);
                IntPtr buffer = Marshal.StringToHGlobalUni(rel);
                UnicodeString us = new UnicodeString();
                us.Length = (ushort)(rel.Length * 2);
                us.MaximumLength = (ushort)(rel.Length * 2 + 2);
                us.Buffer = buffer;
                IntPtr pus = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UnicodeString)));
                try
                {
                    Marshal.StructureToPtr(us, pus, false);
                    ObjectAttributes oa = new ObjectAttributes();
                    oa.Length = Marshal.SizeOf(typeof(ObjectAttributes));
                    oa.RootDirectory = root.DangerousGetHandle();
                    oa.ObjectName = pus;
                    oa.Attributes = ObjCaseInsensitive | (dontReparse ? ObjDontReparse : 0);
                    IoStatusBlock io;
                    SafeFileHandle h;
                    // FILE_GENERIC_READ; share read|write|delete; FILE_OPEN; FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT.
                    int status = NtCreateFile(out h, 0x120089, ref oa, out io, IntPtr.Zero, 0, 7, 1, 0x40 | 0x20, IntPtr.Zero, 0);
                    if (h != null && !h.IsInvalid) h.Dispose();
                    return status;
                }
                finally { Marshal.FreeHGlobal(pus); Marshal.FreeHGlobal(buffer); }
            }
        }
    }
}
