# Credential Manager

## Description

Provides a wrapper around the Credential Manager Win32 API.

## Usage

When writing and reading stored credentials, if not specified, the credential type defaults to CRED_TYPE_GENERIC. Persistance is defaulted to CRED_PERSIST_LOCAL_MACHINE.

### Example 1

*This example sets and retrieves credentials for a Windows Identity*
    Set-CredManCredential -TargetName "john.smith" -UserName "john.smith" -Secret "password" -Comment "My test cred" -Flags CRED_FLAGS_USERNAME_TARGET -Type CRED_TYPE_DOMAIN_PASSWORD
    Get-CredManCredential -TargetName "john.smith" -Type CRED_TYPE_DOMAIN_PASSWORD

### Example 2

*This example creates a generic credential for google.com and then updates it by changing the comment. The original secret is preserved with the specified write flag.*
	
	Set-CredManCredential -TargetName "google.com" -UserName "john.smith" -Secret "password" -Comment "TESTING"
	Set-CredManCredential -TargetName "google.com" -UserName "john.smith" -Comment "Ready To Use" -WriteFlags CRED_PRESERVE_CREDENTIAL_BLOB

### Example 3
*This example retrieves a list of all GENERIC credentials that start with the word Microsoft in the target name.
    $Creds = Get-CredManCredentialList -Filter "Microsoft*"

### Example 4

*This example removes an existing credential for google.com without being prompted for confirmation*
    Remove-CredManCredential -TargetName "google.com" -Force

## Release Notes

### 1.0.0.0
Initial Release.
