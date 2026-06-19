// azure_storage.cs
//
// TEST HARNESS: This file intentionally contains hardcoded Azure credentials
// for secrets detection tool benchmarking. All credentials are FAKE.
// See secrets-manifest.csv for ground truth.

using Azure.Storage.Blobs;
using Azure.Identity;

namespace TestHarness.Config
{
    public static class AzureConfig
    {
        // --- MANIFEST ID 35 ---
        // Azure Storage Account Connection String
        // (real format: DefaultEndpointsProtocol=https;AccountName=...;AccountKey=<base64>;EndpointSuffix=core.windows.net)
        public const string StorageConnectionString =
            "DefaultEndpointsProtocol=https;AccountName=mystorageaccount;AccountKey=FakeAzureStorageAccountKeyBase64EncodedABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+FakeKey==;EndpointSuffix=core.windows.net";

        // --- MANIFEST ID 36 ---
        // Azure Client Secret (used with Service Principal)
        // (format: typically a GUID or high-entropy string)
        public const string AzureClientSecret = "FakeAzureClientSecret~ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop";

        // --- MANIFEST ID 37 ---
        // Azure Tenant ID — NOT a secret (GUID identifying AAD tenant)
        public const string AzureTenantId = "12345678-1234-1234-1234-123456789012";

        // --- MANIFEST ID 38 ---
        // Azure Client ID — NOT a secret (app registration ID)
        public const string AzureClientId = "87654321-4321-4321-4321-210987654321";

        // --- MANIFEST ID 39 ---
        // Azure Subscription Key (API Management gateway key)
        // (format: 32-char hex)
        public const string ApiManagementSubscriptionKey = "fakeazureapimanagementkey1234abcd";

        // --- MANIFEST ID 40 ---
        // Azure Event Hub Connection String
        public const string EventHubConnectionString =
            "Endpoint=sb://mynamespace.servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey=FakeEventHubSharedAccessKeyBase64EncodedABCDE=";

        public static BlobServiceClient GetBlobClient()
        {
            return new BlobServiceClient(StorageConnectionString);
        }

        public static ClientSecretCredential GetServicePrincipal()
        {
            return new ClientSecretCredential(AzureTenantId, AzureClientId, AzureClientSecret);
        }
    }
}
