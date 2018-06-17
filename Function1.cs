using System;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Host;
using Microsoft.Azure.Services.AppAuthentication;
using Microsoft.Azure.KeyVault;
using System.Threading.Tasks;
using Flexinets.Security.Core;

namespace Flexinets.Wandera.PasswordRefresher
{
    public static class Function1
    {
        private const String _vaultUrl = "https://wandera.vault.azure.net";
        private const String _secretName = "RadarPassword";

        [FunctionName("WanderaPasswordRefresher")]
        public static async Task Run([TimerTrigger("0 */5 * * * *")]TimerInfo myTimer, TraceWriter log)
        {
            log.Info($"Updating Radar password: {DateTime.UtcNow}");

            var azureServiceTokenProvider = new AzureServiceTokenProvider();
            var keyvault = new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(azureServiceTokenProvider.KeyVaultTokenCallback));
            var oldPassword = await keyvault.GetSecretAsync(_vaultUrl, _secretName);
            var newPassword = CryptoMethods.GetRandomPassword();
            var foo = await keyvault.SetSecretAsync(_vaultUrl, _secretName, newPassword);
            log.Info("Radar password updated");
        }
    }
}
