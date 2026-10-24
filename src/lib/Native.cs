// AgentTempManager native helpers.
// Written in C# 5 so it compiles under Windows PowerShell 5.1 (CodeDom/csc v4)
// and PowerShell 7 (Roslyn). No external dependencies.
//
// Safety invariants enforced here:
//  * Reparse points (junctions, symlinks, mount points, cloud placeholders) are
//    NEVER traversed. They are counted and reported.
//  * The scanner and the lock probe never write to the filesystem.
//  * The job runner (Git, docs/adr/ADR-0006) creates its child inside a job object of its own and only ever
//    terminates that job; it never opens, signals or terminates any other process.
//  * Read pins (P3-C0) open files and directories for reading only, without write or delete sharing, and never
//    write; they refuse reparse points.
//  * Restart Manager (D-2, P1-C) is used only to list the processes that hold given files open: a session is started,
//    the files are registered, the list is read and the session is always ended. Nothing is shut down or restarted.
//  * The deleter never forces: no attribute changes, no ACL changes, no
//    ownership changes, no privileges. It pins ancestors and the tree by handle
//    (no FILE_SHARE_DELETE) so names cannot be redirected, deletes by handle, aborts
//    before deleting anything on reparse points or protected files, and stops at the
//    first failure.
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace AgentTempManager
{
    public static class AtmNative
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint GetLongPathNameW(string shortPath, StringBuilder longPath, uint bufferLength);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint GetShortPathNameW(string longPath, StringBuilder shortPath, uint bufferLength);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint GetCompressedFileSizeW(string fileName, out uint fileSizeHigh);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool GetDiskFreeSpaceW(string rootPath, out uint sectorsPerCluster, out uint bytesPerSector, out uint freeClusters, out uint totalClusters);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern SafeFileHandle CreateFileW(string fileName, uint desiredAccess, uint shareMode, IntPtr securityAttributes, uint creationDisposition, uint flagsAndAttributes, IntPtr templateFile);

        public static string GetLongPath(string path)
        {
            StringBuilder sb = new StringBuilder(1024);
            uint n = GetLongPathNameW(path, sb, (uint)sb.Capacity);
            if (n == 0) return null;
            if (n > sb.Capacity) { sb = new StringBuilder((int)n + 1); n = GetLongPathNameW(path, sb, (uint)sb.Capacity); if (n == 0) return null; }
            return sb.ToString();
        }

        public static string GetShortPath(string path)
        {
            StringBuilder sb = new StringBuilder(1024);
            uint n = GetShortPathNameW(path, sb, (uint)sb.Capacity);
            if (n == 0) return null;
            if (n > sb.Capacity) { sb = new StringBuilder((int)n + 1); n = GetShortPathNameW(path, sb, (uint)sb.Capacity); if (n == 0) return null; }
            return sb.ToString();
        }

        public static long GetClusterSize(string volumeRoot)
        {
            uint spc, bps, fc, tc;
            if (GetDiskFreeSpaceW(volumeRoot, out spc, out bps, out fc, out tc)) return (long)spc * (long)bps;
            return 4096;
        }

        // Estimated on-disk allocation: compressed/sparse aware size rounded up to cluster.
        // MFT-resident tiny files are overestimated. This is an ESTIMATE.
        public static long EstimateAllocated(string file, long logicalLength, long clusterSize)
        {
            uint high;
            uint low = GetCompressedFileSizeW(file, out high);
            long size = logicalLength;
            if (!(low == 0xFFFFFFFF && Marshal.GetLastWin32Error() != 0))
                size = ((long)high << 32) | low;
            if (clusterSize <= 0) return size;
            return ((size + clusterSize - 1) / clusterSize) * clusterSize;
        }
    }

    // Token information of the CURRENT process only (PRIV-10, docs/adr/ADR-0003). Opens its own token with
    // TOKEN_QUERY; never enables a privilege and never opens another process.
    public static class AtmToken
    {
        const uint TOKEN_QUERY = 0x0008;
        const int TokenElevationTypeClass = 18;
        const int TokenIntegrityLevelClass = 25;

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(IntPtr process, uint desiredAccess, out IntPtr token);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool GetTokenInformation(IntPtr token, int infoClass, IntPtr info, uint length, out uint returnLength);

        [DllImport("advapi32.dll")]
        private static extern IntPtr GetSidSubAuthorityCount(IntPtr sid);

        [DllImport("advapi32.dll")]
        private static extern IntPtr GetSidSubAuthority(IntPtr sid, uint index);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);

        // 1 = default, 2 = full, 3 = limited (TOKEN_ELEVATION_TYPE); 0 when it cannot be read.
        public static int GetElevationType()
        {
            IntPtr token;
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, out token)) return 0;
            IntPtr buf = Marshal.AllocHGlobal(4);
            try
            {
                uint ret;
                if (!GetTokenInformation(token, TokenElevationTypeClass, buf, 4, out ret)) return 0;
                return Marshal.ReadInt32(buf);
            }
            finally { Marshal.FreeHGlobal(buf); CloseHandle(token); }
        }

        // Last sub-authority of the mandatory label SID (0x1000 low, 0x2000 medium, 0x3000 high, 0x4000 system...);
        // -1 when it cannot be read.
        public static long GetIntegrityRid()
        {
            IntPtr token;
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, out token)) return -1;
            IntPtr buf = IntPtr.Zero;
            try
            {
                uint len;
                GetTokenInformation(token, TokenIntegrityLevelClass, IntPtr.Zero, 0, out len);
                if (len == 0 || len > 4096) return -1;
                buf = Marshal.AllocHGlobal((int)len);
                if (!GetTokenInformation(token, TokenIntegrityLevelClass, buf, len, out len)) return -1;
                IntPtr sid = Marshal.ReadIntPtr(buf);   // TOKEN_MANDATORY_LABEL.Label.Sid
                if (sid == IntPtr.Zero) return -1;
                int count = Marshal.ReadByte(GetSidSubAuthorityCount(sid));
                if (count < 1) return -1;
                return (long)(uint)Marshal.ReadInt32(GetSidSubAuthority(sid, (uint)(count - 1)));
            }
            finally { if (buf != IntPtr.Zero) Marshal.FreeHGlobal(buf); CloseHandle(token); }
        }
    }

    public sealed class AtmTreeStats
    {
        public string Path;
        public bool Exists;
        public bool IsDirectory;
        public bool RootIsReparsePoint;
        public long Bytes;
        public long AllocatedBytesEstimate;
        public long Files;
        public long Dirs;            // descendant directories (root excluded)
        public long DirectChildren;
        public long ReparsePoints;
        public long ReadOnlyOrSystemFiles;
        public long ErrorCount;
        public bool MeasurementComplete;
        public DateTime CreationTimeUtc;
        public DateTime LastWriteTimeUtc;
        public DateTime NewestWriteTimeUtc;  // max LastWriteTime over root + all observed descendants
        public List<string> ErrorSamples = new List<string>();
        public List<string> ReparseSamples = new List<string>();

        internal int MaxSamples;

        internal void AddError(string path, Exception ex)
        {
            ErrorCount++;
            MeasurementComplete = false;
            if (ErrorSamples.Count < MaxSamples)
                ErrorSamples.Add(ex.GetType().Name + ": " + path);
        }

        internal void Touch(DateTime t)
        {
            if (t > NewestWriteTimeUtc) NewestWriteTimeUtc = t;
        }
    }

    public static class AtmScanner
    {
        // Single pass over one partition root. Never follows reparse points.
        public static AtmTreeStats ScanTree(string path, int maxSamples, long clusterSize)
        {
            AtmTreeStats s = new AtmTreeStats();
            s.Path = path;
            s.MaxSamples = maxSamples;
            s.MeasurementComplete = true;
            s.NewestWriteTimeUtc = DateTime.MinValue;

            FileAttributes rootAttr;
            try
            {
                rootAttr = File.GetAttributes(path);
            }
            catch (FileNotFoundException) { s.Exists = false; s.MeasurementComplete = false; return s; }
            catch (DirectoryNotFoundException) { s.Exists = false; s.MeasurementComplete = false; return s; }
            catch (Exception ex) { s.Exists = false; s.AddError(path, ex); return s; }

            s.Exists = true;
            s.IsDirectory = (rootAttr & FileAttributes.Directory) != 0;
            if ((rootAttr & FileAttributes.ReparsePoint) != 0)
            {
                s.RootIsReparsePoint = true;
                s.ReparsePoints = 1;
                s.ReparseSamples.Add(path);
                return s;
            }

            try
            {
                FileSystemInfo ri = s.IsDirectory ? (FileSystemInfo)new DirectoryInfo(path) : (FileSystemInfo)new FileInfo(path);
                s.CreationTimeUtc = ri.CreationTimeUtc;
                s.LastWriteTimeUtc = ri.LastWriteTimeUtc;
                s.Touch(s.LastWriteTimeUtc);
                if (!s.IsDirectory)
                {
                    FileInfo f = (FileInfo)ri;
                    s.Files = 1;
                    s.Bytes = f.Length;
                    s.AllocatedBytesEstimate = AtmNative.EstimateAllocated(path, f.Length, clusterSize);
                    if ((rootAttr & (FileAttributes.ReadOnly | FileAttributes.System)) != 0) s.ReadOnlyOrSystemFiles = 1;
                    return s;
                }
            }
            catch (Exception ex) { s.AddError(path, ex); return s; }

            Stack<string> stack = new Stack<string>();
            stack.Push(path);
            bool isRoot = true;
            while (stack.Count > 0)
            {
                string dir = stack.Pop();
                IEnumerator<FileSystemInfo> en;
                try
                {
                    en = new DirectoryInfo(dir).EnumerateFileSystemInfos().GetEnumerator();
                }
                catch (Exception ex) { s.AddError(dir, ex); isRoot = false; continue; }

                using (en)
                {
                    while (true)
                    {
                        FileSystemInfo fi;
                        try
                        {
                            if (!en.MoveNext()) break;
                            fi = en.Current;
                        }
                        catch (Exception ex) { s.AddError(dir, ex); break; }

                        if (isRoot) s.DirectChildren++;
                        try
                        {
                            FileAttributes a = fi.Attributes;
                            if ((a & FileAttributes.ReparsePoint) != 0)
                            {
                                s.ReparsePoints++;
                                if (s.ReparseSamples.Count < maxSamples) s.ReparseSamples.Add(fi.FullName);
                                continue; // never traverse
                            }
                            s.Touch(fi.LastWriteTimeUtc);
                            if ((a & FileAttributes.Directory) != 0)
                            {
                                s.Dirs++;
                                stack.Push(fi.FullName);
                            }
                            else
                            {
                                long len = ((FileInfo)fi).Length;
                                s.Files++;
                                s.Bytes += len;
                                s.AllocatedBytesEstimate += AtmNative.EstimateAllocated(fi.FullName, len, clusterSize);
                                if ((a & (FileAttributes.ReadOnly | FileAttributes.System)) != 0) s.ReadOnlyOrSystemFiles++;
                            }
                        }
                        catch (Exception ex) { s.AddError(fi.FullName, ex); }
                    }
                }
                isRoot = false;
            }
            return s;
        }
    }

    public sealed class AtmProbeResult
    {
        public string Path;
        public long Probed;
        public long InUse;
        public long Denied;
        public long Errors;
        public long ReparsePoints;
        public bool Complete;
        public List<string> Samples = new List<string>();
        public bool Ok { get { return Complete && InUse == 0 && Denied == 0 && Errors == 0 && ReparsePoints == 0; } }
    }

    public static class AtmLockProbe
    {
        const uint DELETE = 0x00010000;
        const uint FILE_READ_ATTRIBUTES = 0x0080;
        const uint OPEN_EXISTING = 3;
        const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
        const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;

        // Opens every file and directory of the tree with DELETE access and share mode 0,
        // then closes the handle immediately. Nothing is read, written, or deleted.
        // A sharing violation means some process holds a handle that would conflict
        // (open data handle, or a directory used as current directory).
        // LIMITATION: handles opened with full sharing (incl. FILE_SHARE_DELETE) that
        // only read attributes are not detectable; the result is a point-in-time check.
        public static AtmProbeResult ProbeTree(string root, int maxSamples)
        {
            AtmProbeResult r = new AtmProbeResult();
            r.Path = root;
            r.Complete = true;
            List<string> dirs = new List<string>();
            Stack<string> stack = new Stack<string>();
            FileAttributes ra;
            try { ra = File.GetAttributes(root); }
            catch (Exception ex) { r.Errors++; r.Complete = false; r.Samples.Add(ex.GetType().Name + ": " + root); return r; }
            if ((ra & FileAttributes.ReparsePoint) != 0) { r.ReparsePoints++; r.Complete = false; r.Samples.Add("REPARSE: " + root); return r; }
            if ((ra & FileAttributes.Directory) == 0) { ProbeOne(root, false, r, maxSamples); return r; }

            stack.Push(root);
            while (stack.Count > 0)
            {
                string dir = stack.Pop();
                dirs.Add(dir);
                IEnumerator<FileSystemInfo> en;
                try { en = new DirectoryInfo(dir).EnumerateFileSystemInfos().GetEnumerator(); }
                catch (Exception ex) { r.Errors++; r.Complete = false; Sample(r, maxSamples, ex.GetType().Name + ": " + dir); continue; }
                using (en)
                {
                    while (true)
                    {
                        FileSystemInfo fi;
                        try { if (!en.MoveNext()) break; fi = en.Current; }
                        catch (Exception ex) { r.Errors++; r.Complete = false; Sample(r, maxSamples, ex.GetType().Name + ": " + dir); break; }
                        FileAttributes a = fi.Attributes;
                        if ((a & FileAttributes.ReparsePoint) != 0) { r.ReparsePoints++; r.Complete = false; Sample(r, maxSamples, "REPARSE: " + fi.FullName); continue; }
                        if ((a & FileAttributes.Directory) != 0) stack.Push(fi.FullName);
                        else ProbeOne(fi.FullName, false, r, maxSamples);
                    }
                }
            }
            foreach (string d in dirs) ProbeOne(d, true, r, maxSamples);
            return r;
        }

        static void Sample(AtmProbeResult r, int max, string s) { if (r.Samples.Count < max) r.Samples.Add(s); }

        static void ProbeOne(string path, bool isDir, AtmProbeResult r, int maxSamples)
        {
            r.Probed++;
            uint flags = FILE_FLAG_OPEN_REPARSE_POINT | (isDir ? FILE_FLAG_BACKUP_SEMANTICS : 0u);
            using (SafeFileHandle h = AtmNative.CreateFileW(path, DELETE | FILE_READ_ATTRIBUTES, 0, IntPtr.Zero, OPEN_EXISTING, flags, IntPtr.Zero))
            {
                if (!h.IsInvalid) return;
                int err = Marshal.GetLastWin32Error();
                if (err == 32 || err == 33) { r.InUse++; Sample(r, maxSamples, "IN_USE: " + path); }
                else if (err == 5) { r.Denied++; Sample(r, maxSamples, "ACCESS_DENIED: " + path); }
                else { r.Errors++; r.Complete = false; Sample(r, maxSamples, "WIN32_" + err + ": " + path); }
            }
        }
    }

    public sealed class AtmDeleteResult
    {
        public string Path;
        public bool Attempted;
        public bool Completed;
        public long FilesDeleted;
        public long DirsDeleted;
        public long FilesPlanned;
        public long DirsPlanned;
        public string AbortReason;
        public string FailedAt;
    }

    // Deletes one directory tree WITHOUT force and WITHOUT trusting names between checks:
    //  1. Every ancestor (volume root excluded) and every directory of the tree is opened top-down and kept
    //     open WITHOUT FILE_SHARE_DELETE (tree directories also WITHOUT FILE_SHARE_WRITE, so an emptied
    //     directory cannot be opened for writing and converted into a reparse point in place). While pinned, no other process can rename, delete or replace any of
    //     them (e.g. swap a directory for a junction), so path resolution below cannot be redirected.
    //  2. Each pinned handle is checked: directory, not a reparse point, final path == expected path.
    //  3. Files are opened with share mode 0 (fails if anyone has them open), checked the same way, and
    //     deleted through their handle (FileDispositionInfo). Directories are deleted bottom-up through
    //     their pinned handles; a directory that is no longer empty makes the operation stop.
    //  4. Anything unexpected (reparse point, read-only/system file, enumeration error, mismatch) aborts
    //     BEFORE the first deletion when found during planning, or stops at the first failure afterwards.
    public static class AtmDeleter
    {
        const uint DELETE = 0x00010000;
        const uint FILE_LIST_DIRECTORY = 0x0001;
        const uint FILE_READ_ATTRIBUTES = 0x0080;
        const uint SYNCHRONIZE = 0x00100000;
        const uint FILE_SHARE_READ = 1, FILE_SHARE_WRITE = 2;
        const uint OPEN_EXISTING = 3;
        const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
        const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
        const uint ATTR_DIRECTORY = 0x10, ATTR_REPARSE = 0x400, ATTR_READONLY = 0x1, ATTR_SYSTEM = 0x4;

        [StructLayout(LayoutKind.Sequential)]
        struct BY_HANDLE_FILE_INFORMATION
        {
            public uint FileAttributes;
            public uint CreationLow, CreationHigh, AccessLow, AccessHigh, WriteLow, WriteHigh;
            public uint VolumeSerialNumber, FileSizeHigh, FileSizeLow, NumberOfLinks, FileIndexHigh, FileIndexLow;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct FILE_DISPOSITION_INFO { [MarshalAs(UnmanagedType.U1)] public bool DeleteFile; }

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool GetFileInformationByHandle(SafeFileHandle h, out BY_HANDLE_FILE_INFORMATION info);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern uint GetFinalPathNameByHandleW(SafeFileHandle h, StringBuilder buf, uint len, uint flags);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool SetFileInformationByHandle(SafeFileHandle h, int infoClass, ref FILE_DISPOSITION_INFO info, uint size);

        sealed class Pinned { public string Path; public int Depth; public SafeFileHandle Handle; }

        static string FinalPath(SafeFileHandle h)
        {
            StringBuilder sb = new StringBuilder(1024);
            uint n = GetFinalPathNameByHandleW(h, sb, (uint)sb.Capacity, 0);
            if (n == 0) return null;
            if (n >= sb.Capacity) { sb = new StringBuilder((int)n + 2); n = GetFinalPathNameByHandleW(h, sb, (uint)sb.Capacity, 0); if (n == 0) return null; }
            string s = sb.ToString();
            if (s.StartsWith(@"\\?\UNC\", StringComparison.Ordinal)) return null;   // never remote
            if (s.StartsWith(@"\\?\", StringComparison.Ordinal)) s = s.Substring(4);
            return s;
        }

        // Opens and validates; returns null and sets 'why' on any problem.
        static SafeFileHandle OpenChecked(string path, bool isDir, uint access, uint share, out string why)
        {
            BY_HANDLE_FILE_INFORMATION ignored;
            return OpenChecked(path, isDir, access, share, out why, out ignored);
        }

        static SafeFileHandle OpenChecked(string path, bool isDir, uint access, uint share, out string why, out BY_HANDLE_FILE_INFORMATION info)
        {
            why = null;
            info = new BY_HANDLE_FILE_INFORMATION();
            uint flags = FILE_FLAG_OPEN_REPARSE_POINT | (isDir ? FILE_FLAG_BACKUP_SEMANTICS : 0u);
            SafeFileHandle h = CtmCreate(path, access, share, flags);
            if (h.IsInvalid) { int e = Marshal.GetLastWin32Error(); h.Dispose(); why = (e == 32 || e == 33 ? "IN_USE" : (e == 5 ? "ACCESS_DENIED" : "WIN32_" + e)) + ": " + path; return null; }
            if (!GetFileInformationByHandle(h, out info)) { h.Dispose(); why = "NO_INFO: " + path; return null; }
            if ((info.FileAttributes & ATTR_REPARSE) != 0) { h.Dispose(); why = "REPARSE_POINT: " + path; return null; }
            bool dir = (info.FileAttributes & ATTR_DIRECTORY) != 0;
            if (dir != isDir) { h.Dispose(); why = "TYPE_CHANGED: " + path; return null; }
            if (!isDir && (info.FileAttributes & (ATTR_READONLY | ATTR_SYSTEM)) != 0) { h.Dispose(); why = "PROTECTED_FILE: " + path; return null; }
            string fp = FinalPath(h);
            if (fp == null || !string.Equals(fp.TrimEnd('\\'), path.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase)) { h.Dispose(); why = "PATH_REDIRECTED: " + path + " -> " + fp; return null; }
            return h;
        }

        static SafeFileHandle CtmCreate(string path, uint access, uint share, uint flags)
        {
            return AtmNative.CreateFileW(path, access, share, IntPtr.Zero, OPEN_EXISTING, flags, IntPtr.Zero);
        }

        // Re-reads attributes through the pinned handle: still a directory, still not a reparse point.
        static bool StillPlainDirectory(SafeFileHandle h)
        {
            BY_HANDLE_FILE_INFORMATION info;
            if (!GetFileInformationByHandle(h, out info)) return false;
            return (info.FileAttributes & ATTR_DIRECTORY) != 0 && (info.FileAttributes & ATTR_REPARSE) == 0;
        }

        static bool Dispose(SafeFileHandle h)
        {
            FILE_DISPOSITION_INFO d = new FILE_DISPOSITION_INFO();
            d.DeleteFile = true;
            return SetFileInformationByHandle(h, 4 /* FileDispositionInfo */, ref d, (uint)Marshal.SizeOf(typeof(FILE_DISPOSITION_INFO)));
        }

        // Overloads without an expected measurement exist for the test suite only. The clean engine always calls
        // the checked overload with the measurement it has just validated.
        public static AtmDeleteResult DeleteTree(string root) { return DeleteTree(root, -1, -1, -1, -1, null); }
        public static AtmDeleteResult DeleteTree(string root, Action<string> afterPinning) { return DeleteTree(root, -1, -1, -1, -1, afterPinning); }

        // expected*: validated measurement (files, descendant dirs, logical bytes, newest write ticks UTC). Once
        // everything is pinned, the plan must match it exactly, otherwise nothing is deleted.
        // afterPinning: test hook invoked once everything is pinned and planned, before the first deletion.
        public static AtmDeleteResult DeleteTree(string root, long expectedFiles, long expectedDirs, long expectedBytes, long expectedNewestTicksUtc, Action<string> afterPinning)
        {
            AtmDeleteResult r = new AtmDeleteResult();
            r.Path = root;
            List<SafeFileHandle> ancestors = new List<SafeFileHandle>();
            List<Pinned> dirs = new List<Pinned>();
            List<string> files = new List<string>();
            List<long> fileWrites = new List<long>();
            long planBytes = 0;
            long planNewest = 0;
            string why;
            try
            {
                if (root == null || root.Length < 4 || root[1] != ':' || root[2] != '\\') { r.AbortReason = "ROOT_INVALID"; return r; }
                string full = System.IO.Path.GetFullPath(root).TrimEnd('\\');
                if (!string.Equals(full, root.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase)) { r.AbortReason = "ROOT_NOT_CANONICAL"; return r; }

                // 1. Pin ancestors top-down (volume root excluded).
                string[] parts = full.Substring(3).Split('\\');
                string cur = full.Substring(0, 3);
                for (int i = 0; i < parts.Length - 1; i++)
                {
                    cur = System.IO.Path.Combine(cur, parts[i]);
                    SafeFileHandle h = OpenChecked(cur, true, FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | SYNCHRONIZE, FILE_SHARE_READ | FILE_SHARE_WRITE, out why);
                    if (h == null) { r.AbortReason = "ANCESTOR_" + why; return r; }
                    ancestors.Add(h);
                }

                // 2. Pin the tree top-down and plan.
                SafeFileHandle rh = OpenChecked(full, true, DELETE | FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | SYNCHRONIZE, FILE_SHARE_READ, out why);
                if (rh == null) { r.AbortReason = "ROOT_" + why; return r; }
                Pinned rp = new Pinned(); rp.Path = full; rp.Depth = 0; rp.Handle = rh;
                dirs.Add(rp);
                try { planNewest = new DirectoryInfo(full).LastWriteTimeUtc.Ticks; } catch (Exception ex) { r.AbortReason = "ROOT_TIME_UNREADABLE: " + ex.GetType().Name; return r; }
                for (int k = 0; k < dirs.Count; k++)
                {
                    Pinned d = dirs[k];
                    try
                    {
                        if (!StillPlainDirectory(d.Handle)) { r.AbortReason = "PINNED_DIR_CHANGED: " + d.Path; return r; }
                        foreach (FileSystemInfo fi in new DirectoryInfo(d.Path).EnumerateFileSystemInfos())
                        {
                            FileAttributes a = fi.Attributes;
                            if ((a & FileAttributes.ReparsePoint) != 0) { r.AbortReason = "REPARSE_POINT_FOUND: " + fi.FullName; return r; }
                            long wt = fi.LastWriteTimeUtc.Ticks;
                            if (wt > planNewest) planNewest = wt;
                            if ((a & FileAttributes.Directory) != 0)
                            {
                                SafeFileHandle ch = OpenChecked(fi.FullName, true, DELETE | FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | SYNCHRONIZE, FILE_SHARE_READ, out why);
                                if (ch == null) { r.AbortReason = "PIN_" + why; return r; }
                                Pinned cp = new Pinned(); cp.Path = fi.FullName; cp.Depth = d.Depth + 1; cp.Handle = ch;
                                dirs.Add(cp);
                            }
                            else
                            {
                                if ((a & (FileAttributes.ReadOnly | FileAttributes.System)) != 0) { r.AbortReason = "PROTECTED_FILE_FOUND: " + fi.FullName; return r; }
                                files.Add(fi.FullName);
                                fileWrites.Add(fi.LastWriteTimeUtc.ToFileTimeUtc());
                                planBytes += ((FileInfo)fi).Length;
                            }
                        }
                    }
                    catch (Exception ex) { r.AbortReason = "ENUMERATION_FAILED: " + ex.GetType().Name + ": " + d.Path; return r; }
                }
                r.FilesPlanned = files.Count;
                r.DirsPlanned = dirs.Count;
                if (expectedFiles >= 0 && (files.Count != expectedFiles || dirs.Count - 1 != expectedDirs || planBytes != expectedBytes || planNewest != expectedNewestTicksUtc))
                {
                    r.AbortReason = "PLAN_DIFFERS_FROM_VALIDATED_MEASUREMENT (files " + files.Count + "/" + expectedFiles + ", dirs " + (dirs.Count - 1) + "/" + expectedDirs + ", bytes " + planBytes + "/" + expectedBytes + ", newest " + planNewest + "/" + expectedNewestTicksUtc + ")";
                    return r;
                }
                if (afterPinning != null) afterPinning(full);
                r.Attempted = true;

                // 3. Files: exclusive open, validate (incl. unchanged write time), delete by handle.
                for (int n = 0; n < files.Count; n++)
                {
                    string f = files[n];
                    BY_HANDLE_FILE_INFORMATION finfo;
                    SafeFileHandle fh = OpenChecked(f, false, DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE, 0, out why, out finfo);
                    if (fh == null) { r.AbortReason = "DELETE_FILE_REFUSED: " + why; r.FailedAt = f; return r; }
                    using (fh)
                    {
                        long w = ((long)finfo.WriteHigh << 32) | finfo.WriteLow;
                        if (w != fileWrites[n]) { r.AbortReason = "FILE_CHANGED_AFTER_PLANNING"; r.FailedAt = f; return r; }
                        if (!Dispose(fh)) { r.AbortReason = "DELETE_FILE_FAILED: WIN32_" + Marshal.GetLastWin32Error(); r.FailedAt = f; return r; }
                    }
                    r.FilesDeleted++;
                }

                // 4. Directories bottom-up through their pinned handles.
                dirs.Sort(delegate (Pinned x, Pinned y) { return y.Depth.CompareTo(x.Depth); });
                foreach (Pinned d in dirs)
                {
                    if (!StillPlainDirectory(d.Handle)) { r.AbortReason = "PINNED_DIR_CHANGED: " + d.Path; r.FailedAt = d.Path; return r; }
                    if (!Dispose(d.Handle)) { r.AbortReason = "DELETE_DIR_FAILED: WIN32_" + Marshal.GetLastWin32Error(); r.FailedAt = d.Path; return r; }
                    d.Handle.Dispose();
                    d.Handle = null;
                    r.DirsDeleted++;
                }
                r.Completed = true;
                return r;
            }
            finally
            {
                foreach (Pinned d in dirs) { if (d.Handle != null) d.Handle.Dispose(); }
                foreach (SafeFileHandle h in ancestors) h.Dispose();
            }
        }
    }

    public sealed class AtmJobResult
    {
        public bool Started;
        public string Error;            // code: JOB_CREATE_FAILED, JOB_LIMITS_FAILED, JOB_LIMITS_MISMATCH, PIPE_FAILED, ATTRIBUTES_FAILED, CREATE_PROCESS_FAILED
        public int Win32Error;
        public int ProcessId;
        public int ExitCode = -1;
        public bool TimedOut;           // the deadline came first: the job was terminated
        public bool JobTerminated;      // TerminateJobObject was called on this run's job (timeout, or members left after the exit)
        public long ElapsedMs;
        public byte[] Output = new byte[0];
        public bool OutputTruncated;
        public byte[] ErrorOutput = new byte[0];
        public bool ErrorTruncated;
        public int TotalProcesses;      // processes that ran in the job
        public long PeakJobMemory;
        public long JobMemoryLimit;     // read back from the job
        public int ActiveProcessLimit;  // read back from the job
    }

    // Read pins (P3-C0, docs/SECURITY-MODEL.md): a handle opened for reading WITHOUT write or delete sharing on a file
    // or directory a Git call reads, held for the whole call. While it is held no process can change, replace, rename
    // or delete that item, or rename a directory above it. A file that does not exist cannot be pinned (creation is not
    // prevented). The item itself must not be a reparse point (it is opened without following one).
    // Path chain check for the diagnose engine (P3-E): the same rule and result codes as Test-AtmPathChain
    // (Engine.Audit.ps1), in native code because the diagnose engine checks thousands of paths per run. From the volume
    // root down to the path: a fixed drive, every component exists, is readable for attributes and is NOT a reparse
    // point. Returns OK | NOT_FOUND | INACCESSIBLE | REPARSE_IN_PATH | UNSUPPORTED_DRIVE | INVALID; -at names the component.
    public static class AtmPathCheck
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint GetFileAttributesW(string fileName);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        private static extern uint GetDriveTypeW(string rootPath);

        public static string Chain(string path, out string at)
        {
            at = path;
            if (string.IsNullOrEmpty(path) || path.Length < 3 || !char.IsLetter(path[0]) || path[0] > 'z' || path[1] != ':' || path[2] != '\\') return "INVALID";
            string root = path.Substring(0, 3);
            if (GetDriveTypeW(root) != 3) { at = root; return "UNSUPPORTED_DRIVE"; }
            // Longer than the plain API reads: refused (never reported as missing, which callers may accept).
            if (path.Length >= 260) return "INACCESSIBLE";
            string cur = root;
            foreach (string p in path.Substring(3).Split('\\'))
            {
                if (p.Length == 0) continue;
                cur = cur.EndsWith("\\") ? cur + p : cur + "\\" + p;
                uint a = GetFileAttributesW(cur);
                if (a == 0xFFFFFFFF)
                {
                    int e = Marshal.GetLastWin32Error();
                    at = cur;
                    return (e == 2 || e == 3) ? "NOT_FOUND" : "INACCESSIBLE";
                }
                if ((a & 0x400) != 0) { at = cur; return "REPARSE_IN_PATH"; }
            }
            at = null;
            return "OK";
        }

        // Kind, size and last-write time of each name under -dir (attributes only, no content), joined: the fingerprint of
        // the cached common part of a preflight.
        public static string Fingerprint(string dir, string[] names)
        {
            StringBuilder sb = new StringBuilder();
            foreach (string n in names)
            {
                string p = n == "." ? dir : Path.Combine(dir, n);
                sb.Append(n).Append('|');
                try
                {
                    if (File.Exists(p)) { FileInfo fi = new FileInfo(p); sb.Append("f|").Append(fi.Length).Append('|').Append(fi.LastWriteTimeUtc.Ticks); }
                    else if (Directory.Exists(p)) { sb.Append("d|").Append(Directory.GetLastWriteTimeUtc(p).Ticks); }
                    else sb.Append('-');
                }
                catch (Exception) { sb.Append('?'); }
                sb.Append(';');
            }
            return sb.ToString();
        }
    }

    // Shared reads (P3-D): a file opened for reading that shares read, write AND delete with everyone (never blocks
    // another process) and is opened WITHOUT following a reparse point; a reparse point or a directory is refused on the
    // handle itself, so a swap after the path check cannot redirect the read.
    public static class AtmSharedRead
    {
        public static SafeFileHandle Open(string path, out string error)
        {
            error = null;
            SafeFileHandle h = AtmNative.CreateFileW(path, 0x80000000, 0x00000007, IntPtr.Zero, 3, 0x00200000, IntPtr.Zero);
            if (h.IsInvalid) { int e = Marshal.GetLastWin32Error(); error = (e == 2 || e == 3) ? "NOT_FOUND" : ("WIN32_" + e); h.Dispose(); return null; }
            uint attrs = AtmReadPin.Attributes(h);
            if (attrs == 0xFFFFFFFF) { error = "WIN32_" + Marshal.GetLastWin32Error(); h.Dispose(); return null; }
            if ((attrs & 0x400) != 0) { error = "REPARSE"; h.Dispose(); return null; }
            if ((attrs & 0x10) != 0) { error = "DIRECTORY"; h.Dispose(); return null; }
            return h;
        }
    }

    public static class AtmReadPin
    {
        [StructLayout(LayoutKind.Sequential)]
        private struct ByHandleFileInformation
        {
            public uint FileAttributes;
            public long CreationTime;
            public long LastAccessTime;
            public long LastWriteTime;
            public uint VolumeSerialNumber;
            public uint FileSizeHigh;
            public uint FileSizeLow;
            public uint NumberOfLinks;
            public uint FileIndexHigh;
            public uint FileIndexLow;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetFileInformationByHandle(SafeFileHandle file, out ByHandleFileInformation info);

        // GENERIC_READ (share access is only recorded for data access), FILE_SHARE_READ only, OPEN_EXISTING,
        // FILE_FLAG_BACKUP_SEMANTICS (directories) | FILE_FLAG_OPEN_REPARSE_POINT. Returns null with -error NOT_FOUND,
        // REPARSE or WIN32_<code> (32: someone else holds it open for writing).
        public static SafeFileHandle Open(string path, out string error)
        {
            error = null;
            SafeFileHandle h = AtmNative.CreateFileW(path, 0x80000000, 0x00000001, IntPtr.Zero, 3, 0x02000000 | 0x00200000, IntPtr.Zero);
            if (h.IsInvalid)
            {
                int e = Marshal.GetLastWin32Error();
                error = (e == 2 || e == 3) ? "NOT_FOUND" : ("WIN32_" + e);
                h.Dispose();
                return null;
            }
            uint attrs = Attributes(h);
            if (attrs == 0xFFFFFFFF) { error = "WIN32_" + Marshal.GetLastWin32Error(); h.Dispose(); return null; }
            if ((attrs & 0x400) != 0) { error = "REPARSE"; h.Dispose(); return null; }
            return h;
        }

        // File attributes read from an open handle (0xFFFFFFFF on failure).
        internal static uint Attributes(SafeFileHandle h)
        {
            ByHandleFileInformation info;
            if (!GetFileInformationByHandle(h, out info)) return 0xFFFFFFFF;
            return info.FileAttributes;
        }
    }

    // D-2 (docs/adr/ADR-0004, P1-C): which processes hold given files open, through Restart Manager. Only
    // RmStartSession, RmRegisterResources, RmGetList and RmEndSession are used; the session is ended in every case.
    // Returns a status (OK, PARTIAL when more processes hold the files than -maxProcesses, or FAILED_<code>) and, per
    // holder, "pid|startTicksUtc" (the process start time Restart Manager reports, 100 ns). Application and service
    // names are not returned. RmGetList has no cancellation: callers keep the number of files small.
    public static class AtmRestartManager
    {
        [StructLayout(LayoutKind.Sequential)]
        // FILETIME is two DWORDs (4-byte aligned): a long here would add padding and shift every field.
        private struct RmUniqueProcess { public int ProcessId; public uint StartLow; public uint StartHigh; }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct RmProcessInfo
        {
            public RmUniqueProcess Process;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string AppName;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)] public string ServiceShortName;
            public int ApplicationType;
            public uint AppStatus;
            public uint TSSessionId;
            [MarshalAs(UnmanagedType.Bool)] public bool Restartable;
        }

        [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
        private static extern int RmStartSession(out uint sessionHandle, int flags, StringBuilder sessionKey);
        [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
        private static extern int RmRegisterResources(uint sessionHandle, uint nFiles, string[] files, uint nApplications, IntPtr applications, uint nServices, IntPtr services);
        [DllImport("rstrtmgr.dll")]
        private static extern int RmGetList(uint sessionHandle, out uint needed, ref uint count, [In, Out] RmProcessInfo[] info, out uint rebootReasons);
        [DllImport("rstrtmgr.dll")]
        private static extern int RmEndSession(uint sessionHandle);

        public static string Query(string[] files, int maxProcesses, out string[] holders)
        {
            holders = new string[0];
            if (files == null || files.Length == 0) return "OK";
            if (maxProcesses < 1) maxProcesses = 1;
            uint session;
            int rc = RmStartSession(out session, 0, new StringBuilder(64));
            if (rc != 0) return "FAILED_START_" + rc;
            try
            {
                rc = RmRegisterResources(session, (uint)files.Length, files, 0, IntPtr.Zero, 0, IntPtr.Zero);
                if (rc != 0) return "FAILED_REGISTER_" + rc;
                uint needed, reasons;
                uint count = (uint)maxProcesses;
                RmProcessInfo[] info = new RmProcessInfo[maxProcesses];
                rc = RmGetList(session, out needed, ref count, info, out reasons);
                bool partial = false;
                if (rc == 234) { partial = true; count = 0; } // ERROR_MORE_DATA: more holders than the cap
                else if (rc != 0) return "FAILED_LIST_" + rc;
                List<string> list = new List<string>();
                for (int i = 0; i < count && i < info.Length; i++)
                {
                    long ticks = 0;
                    long ft = ((long)info[i].Process.StartHigh << 32) | info[i].Process.StartLow;
                    try { ticks = DateTime.FromFileTimeUtc(ft).Ticks; } catch (ArgumentOutOfRangeException) { ticks = 0; }
                    list.Add(info[i].Process.ProcessId + "|" + ticks);
                    info[i].AppName = null; info[i].ServiceShortName = null;
                }
                holders = list.ToArray();
                return partial ? "PARTIAL" : "OK";
            }
            finally { RmEndSession(session); }
        }
    }

    // Bounded execution of one program inside a job object created for that run (docs/adr/ADR-0006 rules 10-11, D-4).
    // The child is created INSIDE the job (PROC_THREAD_ATTRIBUTE_JOB_LIST): when that is not possible nothing runs. It
    // inherits only stdin (NUL), stdout and stderr (PROC_THREAD_ATTRIBUTE_HANDLE_LIST). The job kills its processes when
    // its handle is closed, limits memory and the number of active processes, allows no breakaway, and is the only thing
    // ever terminated (TerminateJobObject on this run's own job handle). No other process is opened, signalled or
    // terminated.
    public static class AtmJobRunner
    {
        const uint JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008;
        const uint JOB_OBJECT_LIMIT_JOB_MEMORY = 0x00000200;
        const uint JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION = 0x00000400;
        const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;
        const int JobObjectBasicAccountingInformation = 1;
        const int JobObjectExtendedLimitInformation = 9;
        const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
        const uint CREATE_NO_WINDOW = 0x08000000;
        const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
        const int STARTF_USESTDHANDLES = 0x00000100;
        const uint HANDLE_FLAG_INHERIT = 0x00000001;
        const uint GENERIC_READ = 0x80000000;
        const uint FILE_SHARE_READ = 0x1;
        const uint FILE_SHARE_WRITE = 0x2;
        const uint OPEN_EXISTING = 3;
        const uint WAIT_OBJECT_0 = 0;
        static readonly IntPtr PROC_THREAD_ATTRIBUTE_HANDLE_LIST = new IntPtr(0x00020002);
        static readonly IntPtr PROC_THREAD_ATTRIBUTE_JOB_LIST = new IntPtr(0x0002000D);

        [StructLayout(LayoutKind.Sequential)]
        struct JOBOBJECT_BASIC_LIMIT_INFORMATION
        {
            public long PerProcessUserTimeLimit;
            public long PerJobUserTimeLimit;
            public uint LimitFlags;
            public UIntPtr MinimumWorkingSetSize;
            public UIntPtr MaximumWorkingSetSize;
            public uint ActiveProcessLimit;
            public UIntPtr Affinity;
            public uint PriorityClass;
            public uint SchedulingClass;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct IO_COUNTERS
        {
            public ulong ReadOperationCount;
            public ulong WriteOperationCount;
            public ulong OtherOperationCount;
            public ulong ReadTransferCount;
            public ulong WriteTransferCount;
            public ulong OtherTransferCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
        {
            public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
            public IO_COUNTERS IoInfo;
            public UIntPtr ProcessMemoryLimit;
            public UIntPtr JobMemoryLimit;
            public UIntPtr PeakProcessMemoryUsed;
            public UIntPtr PeakJobMemoryUsed;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct JOBOBJECT_BASIC_ACCOUNTING_INFORMATION
        {
            public long TotalUserTime;
            public long TotalKernelTime;
            public long ThisPeriodTotalUserTime;
            public long ThisPeriodTotalKernelTime;
            public uint TotalPageFaultCount;
            public uint TotalProcesses;
            public uint ActiveProcesses;
            public uint TotalTerminatedProcesses;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public int bInheritHandle;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct STARTUPINFO
        {
            public int cb;
            public IntPtr lpReserved;
            public IntPtr lpDesktop;
            public IntPtr lpTitle;
            public int dwX;
            public int dwY;
            public int dwXSize;
            public int dwYSize;
            public int dwXCountChars;
            public int dwYCountChars;
            public int dwFillAttribute;
            public int dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct STARTUPINFOEX
        {
            public STARTUPINFO StartupInfo;
            public IntPtr lpAttributeList;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern IntPtr CreateJobObjectW(IntPtr attributes, string name);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool SetInformationJobObject(IntPtr job, int infoClass, ref JOBOBJECT_EXTENDED_LIMIT_INFORMATION info, uint length);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool QueryInformationJobObject(IntPtr job, int infoClass, out JOBOBJECT_EXTENDED_LIMIT_INFORMATION info, uint length, IntPtr returnLength);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool QueryInformationJobObject(IntPtr job, int infoClass, out JOBOBJECT_BASIC_ACCOUNTING_INFORMATION info, uint length, IntPtr returnLength);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool TerminateJobObject(IntPtr job, uint exitCode);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CreatePipe(out IntPtr readPipe, out IntPtr writePipe, ref SECURITY_ATTRIBUTES attributes, uint size);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool SetHandleInformation(IntPtr handle, uint mask, uint flags);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern IntPtr CreateFileW(string fileName, uint desiredAccess, uint shareMode, ref SECURITY_ATTRIBUTES attributes, uint creationDisposition, uint flags, IntPtr template);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool InitializeProcThreadAttributeList(IntPtr list, int count, int flags, ref IntPtr size);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool UpdateProcThreadAttribute(IntPtr list, uint flags, IntPtr attribute, IntPtr value, IntPtr size, IntPtr previousValue, IntPtr returnSize);
        [DllImport("kernel32.dll")]
        static extern void DeleteProcThreadAttributeList(IntPtr list);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool CreateProcessW(string application, StringBuilder commandLine, IntPtr processAttributes, IntPtr threadAttributes, bool inheritHandles, uint flags, IntPtr environment, string currentDirectory, ref STARTUPINFOEX startupInfo, out PROCESS_INFORMATION processInformation);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool GetExitCodeProcess(IntPtr process, out int exitCode);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr handle);

        sealed class Reader
        {
            readonly FileStream stream;
            readonly int cap;
            readonly MemoryStream kept = new MemoryStream();
            public bool Truncated;
            public System.Threading.Thread Thread;
            public Reader(IntPtr handle, int cap)
            {
                stream = new FileStream(new SafeFileHandle(handle, true), FileAccess.Read, 4096, false);
                this.cap = cap;
                Thread = new System.Threading.Thread(Run);
                Thread.IsBackground = true;
                Thread.Start();
            }
            void Run()
            {
                // Everything is read so the child never blocks on a full pipe; only the first cap bytes are kept.
                byte[] buf = new byte[8192];
                try
                {
                    int n;
                    while ((n = stream.Read(buf, 0, buf.Length)) > 0)
                    {
                        int room = cap - (int)kept.Length;
                        if (room > 0) kept.Write(buf, 0, Math.Min(room, n));
                        if (n > room) Truncated = true;
                    }
                }
                catch (IOException) { }
                catch (ObjectDisposedException) { }
                finally { stream.Dispose(); }
            }
            public byte[] Bytes { get { return kept.ToArray(); } }
        }

        // application: absolute path of the program. commandLine: the full command line (program name first), already
        // validated by the caller. environment: KEY=VALUE pairs (the whole environment of the child). Limits: timeout
        // (ms), bytes kept per output stream, job memory (bytes) and active processes.
        public static AtmJobResult Run(string application, string commandLine, string workingDirectory, string[] environment, int timeoutMs, int maxOutputBytes, long jobMemoryBytes, int activeProcessLimit)
        {
            if (timeoutMs < 0 || maxOutputBytes < 1 || jobMemoryBytes < 1048576 || activeProcessLimit < 1 || application == null || commandLine == null || environment == null)
                throw new ArgumentOutOfRangeException("limits");
            AtmJobResult r = new AtmJobResult();
            System.Diagnostics.Stopwatch sw = System.Diagnostics.Stopwatch.StartNew();
            IntPtr job = IntPtr.Zero, outRead = IntPtr.Zero, outWrite = IntPtr.Zero, errRead = IntPtr.Zero, errWrite = IntPtr.Zero, nul = IntPtr.Zero;
            IntPtr attrList = IntPtr.Zero, handleArray = IntPtr.Zero, jobArray = IntPtr.Zero, envBlock = IntPtr.Zero;
            bool attrInit = false;
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
            Reader outReader = null, errReader = null;
            try
            {
                job = CreateJobObjectW(IntPtr.Zero, null);
                if (job == IntPtr.Zero) { r.Error = "JOB_CREATE_FAILED"; r.Win32Error = Marshal.GetLastWin32Error(); return r; }
                JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
                limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_JOB_MEMORY | JOB_OBJECT_LIMIT_ACTIVE_PROCESS | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
                limits.BasicLimitInformation.ActiveProcessLimit = (uint)activeProcessLimit;
                limits.JobMemoryLimit = new UIntPtr((ulong)jobMemoryBytes);
                uint size = (uint)Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
                if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, ref limits, size)) { r.Error = "JOB_LIMITS_FAILED"; r.Win32Error = Marshal.GetLastWin32Error(); return r; }
                // Read back: the limits in force, and a check of the structure layout on this architecture.
                JOBOBJECT_EXTENDED_LIMIT_INFORMATION back;
                if (!QueryInformationJobObject(job, JobObjectExtendedLimitInformation, out back, size, IntPtr.Zero)) { r.Error = "JOB_LIMITS_FAILED"; r.Win32Error = Marshal.GetLastWin32Error(); return r; }
                r.JobMemoryLimit = (long)back.JobMemoryLimit.ToUInt64();
                r.ActiveProcessLimit = (int)back.BasicLimitInformation.ActiveProcessLimit;
                uint wanted = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_JOB_MEMORY | JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
                if ((back.BasicLimitInformation.LimitFlags & wanted) != wanted || r.JobMemoryLimit != jobMemoryBytes || r.ActiveProcessLimit != activeProcessLimit) { r.Error = "JOB_LIMITS_MISMATCH"; return r; }

                SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES();
                sa.nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES));
                sa.bInheritHandle = 1;
                if (!CreatePipe(out outRead, out outWrite, ref sa, 0) || !CreatePipe(out errRead, out errWrite, ref sa, 0)) { r.Error = "PIPE_FAILED"; r.Win32Error = Marshal.GetLastWin32Error(); return r; }
                SetHandleInformation(outRead, HANDLE_FLAG_INHERIT, 0);
                SetHandleInformation(errRead, HANDLE_FLAG_INHERIT, 0);
                nul = CreateFileW("NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, ref sa, OPEN_EXISTING, 0, IntPtr.Zero);
                if (nul == IntPtr.Zero || nul == new IntPtr(-1)) { nul = IntPtr.Zero; r.Error = "PIPE_FAILED"; r.Win32Error = Marshal.GetLastWin32Error(); return r; }

                // Two attributes: the handles the child inherits, and the job it is created in.
                IntPtr listSize = IntPtr.Zero;
                InitializeProcThreadAttributeList(IntPtr.Zero, 2, 0, ref listSize);
                attrList = Marshal.AllocHGlobal(listSize);
                if (!InitializeProcThreadAttributeList(attrList, 2, 0, ref listSize)) { r.Error = "ATTRIBUTES_FAILED"; r.Win32Error = Marshal.GetLastWin32Error(); return r; }
                attrInit = true;
                handleArray = Marshal.AllocHGlobal(IntPtr.Size * 3);
                Marshal.WriteIntPtr(handleArray, 0, nul);
                Marshal.WriteIntPtr(handleArray, IntPtr.Size, outWrite);
                Marshal.WriteIntPtr(handleArray, IntPtr.Size * 2, errWrite);
                if (!UpdateProcThreadAttribute(attrList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, handleArray, new IntPtr(IntPtr.Size * 3), IntPtr.Zero, IntPtr.Zero)) { r.Error = "ATTRIBUTES_FAILED"; r.Win32Error = Marshal.GetLastWin32Error(); return r; }
                jobArray = Marshal.AllocHGlobal(IntPtr.Size);
                Marshal.WriteIntPtr(jobArray, job);
                if (!UpdateProcThreadAttribute(attrList, 0, PROC_THREAD_ATTRIBUTE_JOB_LIST, jobArray, new IntPtr(IntPtr.Size), IntPtr.Zero, IntPtr.Zero)) { r.Error = "ATTRIBUTES_FAILED"; r.Win32Error = Marshal.GetLastWin32Error(); return r; }

                StringBuilder env = new StringBuilder();
                foreach (string kv in environment) { env.Append(kv); env.Append('\0'); }
                env.Append('\0');
                envBlock = Marshal.StringToHGlobalUni(env.ToString());

                STARTUPINFOEX si = new STARTUPINFOEX();
                si.StartupInfo.cb = Marshal.SizeOf(typeof(STARTUPINFOEX));
                si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
                si.StartupInfo.hStdInput = nul;
                si.StartupInfo.hStdOutput = outWrite;
                si.StartupInfo.hStdError = errWrite;
                si.lpAttributeList = attrList;
                StringBuilder cmd = new StringBuilder(commandLine);
                if (!CreateProcessW(application, cmd, IntPtr.Zero, IntPtr.Zero, true, EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT, envBlock, workingDirectory, ref si, out pi))
                {
                    r.Error = "CREATE_PROCESS_FAILED"; r.Win32Error = Marshal.GetLastWin32Error(); return r;
                }
                r.Started = true;
                r.ProcessId = pi.dwProcessId;
                // The parent keeps no write end: the readers see the end of the output when the job's processes close it.
                CloseHandle(outWrite); outWrite = IntPtr.Zero;
                CloseHandle(errWrite); errWrite = IntPtr.Zero;
                outReader = new Reader(outRead, maxOutputBytes); outRead = IntPtr.Zero;
                errReader = new Reader(errRead, maxOutputBytes); errRead = IntPtr.Zero;

                uint wait = WaitForSingleObject(pi.hProcess, (uint)Math.Max(0, timeoutMs));
                if (wait != WAIT_OBJECT_0)
                {
                    r.TimedOut = true;
                    r.JobTerminated = TerminateJobObject(job, 1);
                    WaitForSingleObject(pi.hProcess, 10000);
                }
                // Members still holding the output (a grandchild) end with the job.
                if (!outReader.Thread.Join(2000) || !errReader.Thread.Join(500))
                {
                    if (TerminateJobObject(job, 1)) r.JobTerminated = true;
                    outReader.Thread.Join(5000); errReader.Thread.Join(5000);
                }
                int code;
                if (GetExitCodeProcess(pi.hProcess, out code)) r.ExitCode = code;
                JOBOBJECT_BASIC_ACCOUNTING_INFORMATION acc;
                if (QueryInformationJobObject(job, JobObjectBasicAccountingInformation, out acc, (uint)Marshal.SizeOf(typeof(JOBOBJECT_BASIC_ACCOUNTING_INFORMATION)), IntPtr.Zero)) r.TotalProcesses = (int)acc.TotalProcesses;
                JOBOBJECT_EXTENDED_LIMIT_INFORMATION after;
                if (QueryInformationJobObject(job, JobObjectExtendedLimitInformation, out after, size, IntPtr.Zero)) r.PeakJobMemory = (long)after.PeakJobMemoryUsed.ToUInt64();
                r.Output = outReader.Bytes; r.OutputTruncated = outReader.Truncated;
                r.ErrorOutput = errReader.Bytes; r.ErrorTruncated = errReader.Truncated;
                return r;
            }
            finally
            {
                if (pi.hThread != IntPtr.Zero) CloseHandle(pi.hThread);
                if (pi.hProcess != IntPtr.Zero) CloseHandle(pi.hProcess);
                if (outWrite != IntPtr.Zero) CloseHandle(outWrite);
                if (errWrite != IntPtr.Zero) CloseHandle(errWrite);
                if (outRead != IntPtr.Zero) CloseHandle(outRead);
                if (errRead != IntPtr.Zero) CloseHandle(errRead);
                if (nul != IntPtr.Zero) CloseHandle(nul);
                if (attrInit) DeleteProcThreadAttributeList(attrList);
                if (attrList != IntPtr.Zero) Marshal.FreeHGlobal(attrList);
                if (handleArray != IntPtr.Zero) Marshal.FreeHGlobal(handleArray);
                if (jobArray != IntPtr.Zero) Marshal.FreeHGlobal(jobArray);
                if (envBlock != IntPtr.Zero) Marshal.FreeHGlobal(envBlock);
                // Closing the job kills whatever is still in it (KILL_ON_JOB_CLOSE): nothing started here outlives the run.
                if (job != IntPtr.Zero) CloseHandle(job);
                sw.Stop();
                r.ElapsedMs = sw.ElapsedMilliseconds;
            }
        }
    }
}
