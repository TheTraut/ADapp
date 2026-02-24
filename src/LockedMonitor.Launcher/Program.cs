using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Windows.Forms;

[assembly: AssemblyTitle("Locked Monitor Launcher")]
[assembly: AssemblyDescription("Launcher for ADapp Locked Users Monitor")]
[assembly: AssemblyCompany("")]
[assembly: AssemblyProduct("ADapp")]
[assembly: AssemblyCopyright("Copyright © 2024-2026")]
[assembly: AssemblyVersion("1.0.19.0")]
[assembly: AssemblyFileVersion("1.0.19.0")]

internal static class Program
{
    [STAThread]
    private static void Main()
    {
        string exeDir = AppDomain.CurrentDomain.BaseDirectory;
        string scriptPath = Path.Combine(exeDir, "LockedMonitor.ps1");

        if (!File.Exists(scriptPath))
        {
            MessageBox.Show(
                "LockedMonitor.ps1 not found at:\n" + scriptPath,
                "Locked Monitor Launcher",
                MessageBoxButtons.OK,
                MessageBoxIcon.Error);
            Environment.Exit(1);
            return;
        }

        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = "-NoProfile -NoLogo -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File \"" + scriptPath + "\"",
                WorkingDirectory = Path.GetDirectoryName(scriptPath) ?? exeDir,
                UseShellExecute = false,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden
            };

            Process.Start(psi);
        }
        catch (Exception ex)
        {
            MessageBox.Show(
                "Failed to start Locked Monitor:\n" + ex.Message,
                "Locked Monitor Launcher Error",
                MessageBoxButtons.OK,
                MessageBoxIcon.Error);
            Environment.Exit(1);
        }
    }
}
