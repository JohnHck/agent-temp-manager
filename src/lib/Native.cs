// AgentTempManager native helpers.
// Written in C# 5 so it compiles under Windows PowerShell 5.1 (CodeDom/csc v4)
// and PowerShell 7 (Roslyn). No external dependencies.
//
// Safety invariants enforced here:
//  * Reparse points (junctions, symlinks, mount points, cloud placeholders) are
//    NEVER traversed. They are counted and reported.
//  * The scanner and the lock probe never write to the filesystem.
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
        internal struct BY_HANDLE_FILE_INFORMATION
        {
            public uint FileAttributes;
            public uint CreationLow, CreationHigh, AccessLow, AccessHigh, WriteLow, WriteHigh;
            public uint VolumeSerialNumber, FileSizeHigh, FileSizeLow, NumberOfLinks, FileIndexHigh, FileIndexLow;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct FILE_DISPOSITION_INFO { [MarshalAs(UnmanagedType.U1)] public bool DeleteFile; }

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool GetFileInformationByHandle(SafeFileHandle h, out BY_HANDLE_FILE_INFORMATION info);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern uint GetFinalPathNameByHandleW(SafeFileHandle h, StringBuilder buf, uint len, uint flags);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool SetFileInformationByHandle(SafeFileHandle h, int infoClass, ref FILE_DISPOSITION_INFO info, uint size);

        sealed class Pinned { public string Path; public int Depth; public SafeFileHandle Handle; }

        internal static string FinalPath(SafeFileHandle h)
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
        internal static SafeFileHandle OpenChecked(string path, bool isDir, uint access, uint share, out string why)
        {
            BY_HANDLE_FILE_INFORMATION ignored;
            return OpenChecked(path, isDir, access, share, out why, out ignored);
        }

        internal static SafeFileHandle OpenChecked(string path, bool isDir, uint access, uint share, out string why, out BY_HANDLE_FILE_INFORMATION info)
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
        internal static bool StillPlainDirectory(SafeFileHandle h)
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

    // Safe creation of a new file (FINAL-A, export ancestor TOCTOU). Pin(): every ancestor below the volume root is opened
    // top-down without following reparse points (FILE_FLAG_OPEN_REPARSE_POINT), refused when it is a reparse point, not a
    // directory or reached through a redirection (final path through the handle), and kept open without FILE_SHARE_DELETE
    // so it cannot be renamed, deleted or replaced while pinned. The parent (often empty) can still be turned into a
    // junction in place through another handle with FILE_WRITE_ATTRIBUTES (share modes do not govern that right):
    // CreateNew() therefore re-checks it before and after creating and refuses (PARENT_CHANGED), and the creation is
    // relative to the handle with OBJ_DONT_REPARSE, so no reparse point is followed. CreateNew(): creates the file RELATIVE TO
    // THE PARENT HANDLE (NtCreateFile, RootDirectory, OBJ_DONT_REPARSE, FILE_OPEN_REPARSE_POINT, FILE_CREATE: never an
    // existing name, never through a reparse point) with a protected DACL (its owner, SYSTEM, Administrators),
    // verifies the created file through its handle (not a reparse point, same volume, final path as expected) and only
    // then writes. Nothing is written when anything is inconclusive (fail closed); an empty file may then remain.
    public sealed class AtmSafeCreateSession : IDisposable
    {
        internal List<SafeFileHandle> Pins = new List<SafeFileHandle>();
        internal SafeFileHandle Parent;
        internal uint VolumeSerial;
        public string ParentPath;
        public string Error;
        public bool IsPinned { get { return Error == null && Parent != null && !Parent.IsInvalid && !Parent.IsClosed; } }
        public void Dispose()
        {
            if (Parent != null) { Parent.Dispose(); Parent = null; }
            for (int i = Pins.Count - 1; i >= 0; i--) { Pins[i].Dispose(); }
            Pins.Clear();
        }
    }

    public static class AtmSafeCreate
    {
        const uint FILE_LIST_DIRECTORY = 0x0001, FILE_READ_ATTRIBUTES = 0x0080, SYNCHRONIZE = 0x00100000;
        const uint FILE_SHARE_READ = 1, FILE_SHARE_WRITE = 2;
        const uint FILE_GENERIC_WRITE = 0x00120116, READ_CONTROL = 0x00020000;
        const uint OBJ_CASE_INSENSITIVE = 0x40, OBJ_DONT_REPARSE = 0x1000;
        const uint FILE_CREATE = 2;
        const uint FILE_SYNCHRONOUS_IO_NONALERT = 0x20, FILE_NON_DIRECTORY_FILE = 0x40, FILE_OPEN_REPARSE_POINT = 0x00200000;
        const uint FILE_ATTRIBUTE_NORMAL = 0x80;
        const uint ATTR_DIRECTORY = 0x10, ATTR_REPARSE = 0x400;

        [StructLayout(LayoutKind.Sequential)]
        struct UNICODE_STRING { public ushort Length; public ushort MaximumLength; public IntPtr Buffer; }

        [StructLayout(LayoutKind.Sequential)]
        struct OBJECT_ATTRIBUTES { public int Length; public IntPtr RootDirectory; public IntPtr ObjectName; public uint Attributes; public IntPtr SecurityDescriptor; public IntPtr SecurityQualityOfService; }

        [StructLayout(LayoutKind.Sequential)]
        struct IO_STATUS_BLOCK { public IntPtr Status; public IntPtr Information; }

        [DllImport("ntdll.dll")]
        static extern int NtCreateFile(out IntPtr fileHandle, uint desiredAccess, ref OBJECT_ATTRIBUTES objectAttributes, out IO_STATUS_BLOCK ioStatusBlock, IntPtr allocationSize, uint fileAttributes, uint shareAccess, uint createDisposition, uint createOptions, IntPtr eaBuffer, uint eaLength);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string sddl, uint revision, out IntPtr securityDescriptor, out uint size);

        [DllImport("kernel32.dll")]
        static extern IntPtr LocalFree(IntPtr mem);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        static extern uint GetDriveTypeW(string rootPath);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern uint QueryDosDeviceW(string deviceName, StringBuilder targetPath, uint max);

        // True when the drive letter of 'path' is a substitution of a folder (subst, DefineDosDevice): its DOS device
        // target names a path ("\??\C:\...") instead of a volume device. Unknown (the query fails) counts as true, so the
        // caller fails closed. Reads the device namespace only. (V0.1.1: inlined from the V0.2 path checks.)
        static bool IsSubstitutedDrive(string path)
        {
            if (string.IsNullOrEmpty(path) || path.Length < 2 || path[1] != ':') return true;
            StringBuilder sb = new StringBuilder(1024);
            uint n = QueryDosDeviceW(path.Substring(0, 2), sb, (uint)sb.Capacity);
            if (n == 0) return true;
            return sb.ToString().StartsWith(@"\??\", StringComparison.Ordinal);
        }

        // Pins the folder that will hold the new file. Check IsPinned / Error; always Dispose.
        public static AtmSafeCreateSession Pin(string parentDir)
        {
            AtmSafeCreateSession s = new AtmSafeCreateSession();
            string why;
            try
            {
                if (parentDir == null || parentDir.Length < 4 || !char.IsLetter(parentDir[0]) || parentDir[0] > 'z' || parentDir[1] != ':' || parentDir[2] != '\\') { s.Error = "PARENT_INVALID"; return s; }
                string full = Path.GetFullPath(parentDir).TrimEnd('\\');
                if (!string.Equals(full, parentDir.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase)) { s.Error = "PARENT_NOT_CANONICAL"; return s; }
                if (full.Length >= 240) { s.Error = "PARENT_TOO_LONG"; return s; }
                if (GetDriveTypeW(full.Substring(0, 3)) != 3) { s.Error = "UNSUPPORTED_DRIVE"; return s; }
                if (IsSubstitutedDrive(full)) { s.Error = "SUBSTITUTED_DRIVE"; return s; }
                s.ParentPath = full;
                string[] parts = full.Substring(3).Split('\\');
                string cur = full.Substring(0, 3);
                for (int i = 0; i < parts.Length - 1; i++)
                {
                    cur = Path.Combine(cur, parts[i]);
                    SafeFileHandle h = AtmDeleter.OpenChecked(cur, true, FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | SYNCHRONIZE, FILE_SHARE_READ | FILE_SHARE_WRITE, out why);
                    if (h == null) { s.Error = "ANCESTOR_" + Code(why); return s; }
                    s.Pins.Add(h);
                }
                AtmDeleter.BY_HANDLE_FILE_INFORMATION info;
                SafeFileHandle p = AtmDeleter.OpenChecked(full, true, FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | SYNCHRONIZE, FILE_SHARE_READ, out why, out info);
                if (p == null) { s.Error = "PARENT_" + Code(why); return s; }
                s.Parent = p;
                s.VolumeSerial = info.VolumeSerialNumber;
                return s;
            }
            catch (Exception ex) { s.Error = "PIN_" + ex.GetType().Name; return s; }
        }

        // Creates fileName in the pinned folder and writes content. Returns null on success, otherwise a code.
        public static string CreateNew(AtmSafeCreateSession s, string fileName, byte[] content)
        {
            if (s == null || !s.IsPinned) return "NOT_PINNED";
            if (!ValidName(fileName)) return "FILE_NAME_INVALID";
            if (!AtmDeleter.StillPlainDirectory(s.Parent)) return "PARENT_CHANGED";
            IntPtr sd = IntPtr.Zero, namePtr = IntPtr.Zero, objName = IntPtr.Zero, raw = IntPtr.Zero;
            SafeFileHandle fh = null;
            bool parentRef = false;
            try
            {
                // Protected DACL: the file's owner (the account that creates it, OW), SYSTEM and Administrators only.
                uint sdSize;
                if (!ConvertStringSecurityDescriptorToSecurityDescriptorW("D:P(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)", 1, out sd, out sdSize)) return "SECURITY_DESCRIPTOR_FAILED";
                namePtr = Marshal.StringToHGlobalUni(fileName);
                UNICODE_STRING us = new UNICODE_STRING();
                us.Length = (ushort)(fileName.Length * 2); us.MaximumLength = (ushort)(fileName.Length * 2); us.Buffer = namePtr;
                objName = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UNICODE_STRING)));
                Marshal.StructureToPtr(us, objName, false);
                s.Parent.DangerousAddRef(ref parentRef);
                OBJECT_ATTRIBUTES oa = new OBJECT_ATTRIBUTES();
                oa.Length = Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES));
                oa.RootDirectory = s.Parent.DangerousGetHandle();
                oa.ObjectName = objName;
                oa.Attributes = OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE;
                oa.SecurityDescriptor = sd;
                IO_STATUS_BLOCK io;
                int st = NtCreateFile(out raw, FILE_GENERIC_WRITE | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE, ref oa, out io, IntPtr.Zero, FILE_ATTRIBUTE_NORMAL, 0, FILE_CREATE, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT, IntPtr.Zero, 0);
                if (st != 0)
                {
                    // Name already taken (a file, a directory, a junction or a symbolic link): never reused.
                    if (st == unchecked((int)0xC0000035) || st == unchecked((int)0xC00000BA)) return "EXISTS";
                    if (st == unchecked((int)0xC0000022)) return "ACCESS_DENIED";
                    if (st == unchecked((int)0xC000000D)) return "CREATE_INVALID_PARAMETER";
                    if (st == unchecked((int)0xC000050B) || st == unchecked((int)0xC0000280)) return "REPARSE_REFUSED";
                    return "NTSTATUS_0x" + st.ToString("X8");
                }
                fh = new SafeFileHandle(raw, true);
                raw = IntPtr.Zero;
                // Verify before writing: a file that is not exactly where it was asked for receives no byte.
                AtmDeleter.BY_HANDLE_FILE_INFORMATION fi;
                if (!AtmDeleter.GetFileInformationByHandle(fh, out fi)) return "CREATED_NO_INFO";
                if ((fi.FileAttributes & (ATTR_REPARSE | ATTR_DIRECTORY)) != 0) return "CREATED_NOT_PLAIN";
                if (fi.VolumeSerialNumber != s.VolumeSerial) return "CREATED_OTHER_VOLUME";
                string fp = AtmDeleter.FinalPath(fh);
                string expected = s.ParentPath + "\\" + fileName;
                if (fp == null || !string.Equals(fp, expected, StringComparison.OrdinalIgnoreCase)) return "CREATED_ELSEWHERE";
                if (!AtmDeleter.StillPlainDirectory(s.Parent)) return "CREATED_PARENT_CHANGED";
                using (FileStream fs = new FileStream(fh, FileAccess.Write))
                {
                    if (content != null && content.Length > 0) fs.Write(content, 0, content.Length);
                    fs.Flush(true);
                }
                fh = null;
                return null;
            }
            // Every refusal once the file exists starts with CREATED_ (an empty or partial file may remain; never written to again).
            catch (Exception ex) { return (fh != null ? "CREATED_" : "CREATE_") + ex.GetType().Name; }
            finally
            {
                if (fh != null) fh.Dispose();
                if (raw != IntPtr.Zero) { SafeFileHandle tmp = new SafeFileHandle(raw, true); tmp.Dispose(); }
                if (parentRef) s.Parent.DangerousRelease();
                if (objName != IntPtr.Zero) Marshal.FreeHGlobal(objName);
                if (namePtr != IntPtr.Zero) Marshal.FreeHGlobal(namePtr);
                if (sd != IntPtr.Zero) LocalFree(sd);
            }
        }

        // One plain name: no separator, stream, wildcard, control character, trailing dot or space, dot names or DOS
        // device names (CON, NUL, AUX, PRN, COM1-9, LPT1-9, with or without an extension).
        public static bool ValidName(string n)
        {
            if (string.IsNullOrEmpty(n) || n.Length > 200) return false;
            if (n == "." || n == ".." || n.EndsWith(".") || n.EndsWith(" ") || n.StartsWith(" ")) return false;
            foreach (char c in n) { if (c < 32 || "\\/:*?\"<>|".IndexOf(c) >= 0) return false; }
            string b = n.Split('.')[0].ToUpperInvariant();
            if (b == "CON" || b == "NUL" || b == "AUX" || b == "PRN" || b == "CONIN$" || b == "CONOUT$") return false;
            if (b.Length == 4 && (b.StartsWith("COM") || b.StartsWith("LPT")) && ((b[3] >= '0' && b[3] <= '9') || b[3] == '\u00B9' || b[3] == '\u00B2' || b[3] == '\u00B3')) return false;
            return true;
        }

        static string Code(string why)
        {
            if (why == null) return "UNKNOWN";
            int i = why.IndexOf(':');
            return i > 0 ? why.Substring(0, i) : why;
        }
    }
}
