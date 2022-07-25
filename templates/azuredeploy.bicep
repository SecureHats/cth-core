@description('Specifies the name of the Function App.')
param functionName string = 'securehats-cth'
param location string = 'westeurope'

var functionName_var = toLower(functionName)
var storageAccountName_var = replace(functionName_var, '-', '')
var keyVaultName_var = functionName_var
var storageSuffix = environment().suffixes.storage
var keyVaultSecretReader = '/subscriptions/${subscription().subscriptionId}/providers/Microsoft.Authorization/roleDefinitions/4633458b-17de-408a-b874-0445c86b69e6'
var uniqueRoleGuidKeyVaultSecretReader_var = guid(keyVaultName.id)

resource functionName_resource 'Microsoft.Insights/components@2015-05-01' = {
  name: functionName_var
  location: location
  kind: 'web'
  properties: {
    Application_Type: 'web'
    ApplicationId: functionName_var
  }
}

resource keyVaultName 'Microsoft.KeyVault/vaults@2021-11-01-preview' = {
  name: keyVaultName_var
  location: location
  properties: {
    sku: {
      family: 'A'
      name: 'standard'
    }
    tenantId: subscription().tenantId
    enabledForDeployment: false
    enabledForDiskEncryption: false
    enabledForTemplateDeployment: true
    enableSoftDelete: true
    enableRbacAuthorization: true
  }
  dependsOn: [
    Microsoft_Web_sites_functionName
  ]
}

resource keyVaultName_AzureWebJobsStorage 'Microsoft.KeyVault/vaults/secrets@2016-10-01' = {
  parent: keyVaultName
  name: 'AzureWebJobsStorage'
  properties: {
    value: 'DefaultEndpointsProtocol=https;AccountName=${toLower(storageAccountName_var)};AccountKey=${listKeys(storageAccountName.id, '2019-06-01').keys[0].value};EndpointSuffix=${toLower(storageSuffix)}'
    contentType: 'string'
    attributes: {
      enabled: true
    }
  }
}

resource uniqueRoleGuidKeyVaultSecretReader 'Microsoft.Authorization/roleAssignments@2020-10-01-preview' = {
  scope: keyVaultName
  name: uniqueRoleGuidKeyVaultSecretReader_var
  properties: {
    roleDefinitionId: keyVaultSecretReader
    principalId: reference(Microsoft_Web_sites_functionName.id, '2019-08-01', 'full').identity.principalId
  }
}

resource Microsoft_Web_serverfarms_functionName 'Microsoft.Web/serverfarms@2022-03-01' = {
  name: functionName_var
  location: location
  sku: {
    name: 'Y1'
    tier: 'Dynamic'
  }
  kind: 'functionapp'
}

resource Microsoft_Web_sites_functionName 'Microsoft.Web/sites@2021-03-01' = {
  name: functionName_var
  location: location
  kind: 'functionapp'
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    serverFarmId: Microsoft_Web_serverfarms_functionName.id
    httpsOnly: true
    clientAffinityEnabled: true
    siteConfig: {
      powerShellVersion: '~7'
    }
  }
  dependsOn: [
    storageAccountName

    functionName_resource
  ]
}

resource functionName_appsettings 'Microsoft.Web/sites/config@2021-03-01' = {
  parent: Microsoft_Web_sites_functionName
  name: 'appsettings'
  kind: 'string'
  properties: {
    APPINSIGHTS_INSTRUMENTATIONKEY: reference(functionName_resource.id, '2015-05-01').InstrumentationKey
    APPLICATIONINSIGHTS_CONNECTION_STRING: reference(functionName_resource.id, '2015-05-01').ConnectionString
    //AzureWebJobsStorage: NF.secretName(keyVaultName_var, 'AzureWebJobsStorage')
    //WEBSITE_CONTENTAZUREFILECONNECTIONSTRING: NF.secretName(keyVaultName_var, 'AzureWebJobsStorage')
    WEBSITE_CONTENTSHARE: toLower(functionName_var)
    WEBSITE_RUN_FROM_PACKAGE: 'https://github.com/SecureHats/cth-core/raw/main/function.zip'
    FUNCTIONS_EXTENSION_VERSION: '~3'
    FUNCTIONS_WORKER_RUNTIME: 'powershell'
  }
  dependsOn: [
    keyVaultName
    keyVaultName_AzureWebJobsStorage
    //extensionResourceId(keyVaultName.id, 'Microsoft.Authorization/roleAssignments/', uniqueRoleGuidKeyVaultSecretReader_var)
    Microsoft_Storage_storageAccounts_fileServices_StorageAccountName_default
  ]
}

resource storageAccountName 'Microsoft.Storage/storageAccounts@2019-06-01' = {
  name: storageAccountName_var
  location: location
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    networkAcls: {
      bypass: 'AzureServices'
      virtualNetworkRules: []
      ipRules: []
      defaultAction: 'Allow'
    }
    minimumTlsVersion: 'TLS1_2'
    allowBlobPublicAccess: false
    supportsHttpsTrafficOnly: true
    encryption: {
      services: {
        file: {
          keyType: 'Account'
          enabled: true
        }
        blob: {
          keyType: 'Account'
          enabled: true
        }
      }
      keySource: 'Microsoft.Storage'
    }
  }
}

resource StorageAccountName_default 'Microsoft.Storage/storageAccounts/blobServices@2019-06-01' = {
  parent: storageAccountName
  name: 'default'
  properties: {
    cors: {
      corsRules: []
    }
    deleteRetentionPolicy: {
      enabled: false
    }
  }
}

resource Microsoft_Storage_storageAccounts_fileServices_StorageAccountName_default 'Microsoft.Storage/storageAccounts/fileServices@2019-06-01' = {
  parent: storageAccountName
  name: 'default'
  properties: {
    cors: {
      corsRules: []
    }
  }
}


output functionAppName string = functionName_var
