using Flexinets.Security.Core;
using log4net;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.Services.AppAuthentication;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Host;
using System;
using System.IO;
using System.Reflection;
using System.Threading.Tasks;

namespace Flexinets.Wandera.PasswordRefresher
{
    public static class WanderaPasswordRefresherFunction
    {
        private static readonly ILog _log = LogManager.GetLogger(typeof(WanderaPasswordRefresherFunction));

        private const String _vaultUrl = "https://wandera.vault.azure.net";
        private const String _secretName = "RadarPassword";
        private const String _username = "api@flexinets.se";

        [FunctionName("WanderaPasswordRefresher")]
        public static async Task Run([TimerTrigger("0 0 0 1,15 * *")]TimerInfo myTimer, TraceWriter log, ExecutionContext context)
        {
            log.Info($"Updating Radar password: {DateTime.UtcNow}");
            log4net.Config.XmlConfigurator.ConfigureAndWatch(LogManager.GetRepository(Assembly.GetEntryAssembly()), new FileInfo(Path.Combine(context.FunctionAppDirectory, "log4net.config")));
            try
            {
                var keyvault = new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(new AzureServiceTokenProvider().KeyVaultTokenCallback));

                var oldPassword = await keyvault.GetSecretAsync(_vaultUrl, _secretName);

                var newPassword = CryptoMethods.GetRandomPassword();

                var client = new RadarApiClient(_username, oldPassword.Value);
                var response = await client.UpdatePasswordAsync(newPassword);
                if (response.Trim() != "")
                {
                    _log.Error($"Unable to set radar password, response: {response}");
                }
                else
                {
                    var result = await keyvault.SetSecretAsync(_vaultUrl, _secretName, newPassword);
                    _log.Info($"Wandera Radar Api password updated, response: {response}");
                }
            }
            catch (Exception ex)
            {
                _log.Error("Wandera password update failed", ex);
                throw;
            }
        }
    }
}
