using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Windows.Forms;

[assembly: AssemblyTitle("ADapp Launcher")]
[assembly: AssemblyDescription("Launcher for ADapp PowerShell Active Directory management tool")]
[assembly: AssemblyCompany("")]
[assembly: AssemblyProduct("ADapp")]
[assembly: AssemblyCopyright("Copyright © 2024-2026")]
[assembly: AssemblyVersion("1.0.17.0")]
[assembly: AssemblyFileVersion("1.0.17.0")]

internal static class Program
{
    [STAThread]
    private static void Main()
    {
        string exeDir = AppDomain.CurrentDomain.BaseDirectory;
        string scriptPath = Path.Combine(exeDir, "ADapp.ps1");

        if (!File.Exists(scriptPath))
        {
            MessageBox.Show(
                "ADapp.ps1 not found at:\n" + scriptPath,
                "ADapp Launcher",
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
                "Failed to start ADapp:\n" + ex.Message,
                "ADapp Launcher Error",
                MessageBoxButtons.OK,
                MessageBoxIcon.Error);
            Environment.Exit(1);
        }
    }
}
